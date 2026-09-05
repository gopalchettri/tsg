"""The treatment plan's Structured Outputs contract (prompts.TreatmentPlanGenerated) and the two
client failure classes it brings (LLMResponseTruncated / LLMRefusal) — no DB, no network.

The schema is what the model is HANDED; _validate_plan is what the server CHECKS; the served
TreatmentPlanDocument is what the API SHOWS. These tests pin the three to each other so a field
added to one without the others fails here, not on a live Azure call or in a customer's GET."""
from __future__ import annotations

# openai's converter is the one litellm calls for a Pydantic response_format (its own wrapper only
# adds {"type":"json_schema","strict":true,"name"}). Imported instead of litellm on purpose: a real
# `import litellm` load_dotenv()s the dev .env into os.environ for the rest of the session.
from openai.lib._pydantic import to_strict_json_schema

from app.api.schemas_treatment import TreatmentPlanDocument
from app.core.enums import ActionPriority, ControlCoverage, ControlType, TreatmentOutcomeReason, YesNo
from app.pipeline.llm import LLMRefusal, LLMResponseTruncated
from app.pipeline.prompts import TreatmentPlanGenerated
from app.pipeline.treatment import _RESERVED_PLAN_KEYS, _classify_failure, _validate_plan


def _walk(node: dict, path: str = ""):
    yield path, node
    for k, v in (node.get("properties") or {}).items():
        yield from _walk(v, f"{path}.{k}")
    if isinstance(node.get("items"), dict):
        yield from _walk(node["items"], path + "[]")
    for i, v in enumerate(node.get("anyOf") or []):
        yield from _walk(v, f"{path}|{i}")
    for k, v in (node.get("$defs") or {}).items():
        yield from _walk(v, f"$defs.{k}")


def _strict_schema() -> dict:
    return to_strict_json_schema(TreatmentPlanGenerated)


def test_schema_compiles_to_the_strict_form_the_provider_demands():
    """Every object: additionalProperties=false and ALL properties required; every leaf typed.
    A future `Any` / `dict[str, Any]` / optional-with-default field fails HERE, before it fails
    as a 400 on the first live call."""
    for path, node in _walk(_strict_schema()):
        if node.get("type") == "object":
            assert node.get("additionalProperties") is False, path
            assert node.get("required") == list(node.get("properties", {})), path
        elif path and not path.startswith("$defs"):
            assert any(k in node for k in ("type", "enum", "$ref", "anyOf")), f"untyped: {path}"


def test_schema_vocabulary_is_the_validators_vocabulary():
    """The enum lists the model may pick from are the SAME members _validate_plan clamps — built
    from the same enums, so the prose, the schema and the check can never disagree."""
    found = {frozenset(node["enum"]) for _, node in _walk(_strict_schema()) if "enum" in node}
    for enum in (ControlType, ActionPriority, ControlCoverage, YesNo):
        assert frozenset(str(v) for v in enum) in found, enum.__name__


def test_keys_partition_between_model_and_server():
    """The model produces exactly what the API serves minus the server-stamped reserved keys —
    never asked for a key nobody serves, never serving a key nobody produces."""
    generated = set(TreatmentPlanGenerated.model_fields)
    served = set(TreatmentPlanDocument.model_fields)
    assert generated.isdisjoint(_RESERVED_PLAN_KEYS), "a reserved key must never be model-authored"
    assert generated <= served
    assert generated | set(_RESERVED_PLAN_KEYS) >= served


def sample_generated_plan() -> TreatmentPlanGenerated:
    """A fully-populated instance — shared with the route-level pin in
    test_treatment_plan_versions (a model that satisfies the schema must satisfy the server)."""
    return TreatmentPlanGenerated(
        title="Identity and Access Management Hardening",
        controls_to_be_implemented={"control_coverage": ControlCoverage.gaps, "controls": [{
            "control_type": ControlType.preventive, "control_name": "MFA for remote access",
            "description": "Stops credential replay against the operator VPN.",
            "priority": ActionPriority.critical, "control_code": "CII-CID-028"}]},
        remediation_action_plan=[{
            "action_id": "A1", "action": "Enrol every remote account in MFA", "owner": "IAM team",
            "priority": ActionPriority.critical, "dependencies": "None", "timeline": "2026-09-01",
            "success_criteria": "100% of remote accounts enrolled, verified by IdP report"}],
        action_plan="A1 closes the gap; urgency follows risk_level Critical (final_risk_rating 20).",
        mitigation_timeline="2026-09-01", mitigation_owner="Head of IAM",
        applicable_to_all_subsystems=YesNo.yes)


def test_a_schema_shaped_document_passes_the_server_check_clean():
    assert _validate_plan(sample_generated_plan().model_dump(mode="json")) == []


def test_truncation_and_refusal_are_named_for_what_they_are():
    """Yesterday's blank reply was reported as 'not usable JSON' (invalid_plan). A cap stop is a
    BUDGET failure -> generation_failed (retryable, a regenerate recovers); a Structured Outputs
    refusal is a guardrail -> content_blocked (the one reason a client must not auto-retry)."""
    truncated = LLMResponseTruncated(max_tokens=4096, completion_tokens=4096, reasoning_tokens=4096)
    assert "reasoning_tokens=4096" in str(truncated)
    assert _classify_failure(truncated) == (
        TreatmentOutcomeReason.generation_failed,
        "the model ran out of output budget before finishing its reply")
    assert _classify_failure(LLMRefusal("I can't help with that."))[0] == TreatmentOutcomeReason.content_blocked
