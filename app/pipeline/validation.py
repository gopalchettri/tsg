""" double-checks that the AI's replies are usable and make
sense, flagging problems for a human to see rather than silently pretending
everything is fine.

LLM response-shape validation — the counterpart to
prompts.py's outbound redaction. `parse_json` raises on malformed output so a
stage fails LOUDLY through the existing `_record_failure` machinery (no new
error plumbing); `validate_scenario` is deterministic-only (SDD §8.4:
grounding/validation is "not a correctness proof") — structural completeness
plus a cheap keyword consistency proxy, no LLM-judge call.
"""
from __future__ import annotations

import json
from typing import Any

from app.core.enums import ValidationStatus


class LLMResponseParseError(Exception):
    """LLM response is not parseable JSON or the wrong top-level type. The message
    deliberately excludes the raw response text — repr(exc) flows into the
    client-visible ErrorMessage/audit/SSE channels; the raw text is persisted to
    Prompt_Log (internal DB) by the caller instead."""

    def __init__(self, stage: str, expected_type: type):
        """Store the failing stage and expected type so callers/handlers can
        report which stage broke without re-parsing the (deliberately omitted) message."""
        self.stage = stage
        self.expected_type = expected_type
        super().__init__(f"{stage}: LLM response failed JSON parsing (expected {expected_type.__name__})")


def parse_json(text: str, *, stage: str, expected_type: type = dict) -> Any:
    """ reads the AI's reply as structured data (JSON); if
    it's broken or the wrong shape, this fails loudly instead of quietly
    making something up.

    Parse an LLM reply as JSON, stripping a ```-fence if present. Raises
    LLMResponseParseError on decode failure OR wrong top-level type (threats must
    be a list, scenario a dict). Never returns a default ([R8]: parse
    failures are terminal stage errors, not silently-fabricated successes)."""
    t = (text or "").strip()
    if t.startswith("```"):
        t = t.strip("`")
        # Slice from the FIRST brace of EITHER kind. A fenced list-of-objects (the threats
        # response shape) starts with '[' but its first '{' is *inside* the array — picking that
        # would corrupt the parse. No brace at all → leave as-is so json.loads raises cleanly.
        starts = [i for i in (t.find("{"), t.find("[")) if i != -1]
        if starts:
            t = t[min(starts):]
    try:
        parsed = json.loads(t)
    except (json.JSONDecodeError, ValueError, RecursionError) as exc:
        # RecursionError: a pathologically nested reply blows json's recursion limit — it must
        # still surface as the typed terminal error, not escape the [R8] stage-error contract.
        raise LLMResponseParseError(stage, expected_type) from exc
    if not isinstance(parsed, expected_type):
        raise LLMResponseParseError(stage, expected_type)
    return parsed


def _check_fields(obj: dict[str, Any], required: tuple[str, ...]) -> list[str]:
    """ checks that a list of required fields are all
    actually filled in with real text.

    Shared structural check validate_scenario uses: a field
    counts as missing if absent, None, or blank/whitespace-only, not just absent."""
    return [f"missing {f}" for f in required if not str(obj.get(f) or "").strip()]


def _result(errors: list[str]) -> dict[str, Any]:
    """Shared ValidationJSON envelope validate_scenario uses —
    any error at all downgrades status to warning, never a hard failure."""
    status = ValidationStatus.ok if not errors else ValidationStatus.warning
    return {"validation_status": str(status), "errors": errors}


def _normalize_str_list(raw: Any) -> list[str]:
    """A malformed assumptions/excluded_details field from the model (a bare
    string, null, or a list containing non-strings) must never reach the caller
    as-is — mirrors grounding's actor normalization. Pass-through informational
    data only: never affects validation_status.

    In plain terms: always returns a list of strings — a lone string becomes a
    one-item list, and anything else that isn't a list of strings becomes []."""
    if isinstance(raw, str):
        return [raw]
    if isinstance(raw, list):
        return [x for x in raw if isinstance(x, str)]
    return []


def validate_scenario(scenario: dict[str, Any], threat_type: str | None, threat_name: str | None) -> dict[str, Any]:
    """ sanity-checks the Stage-2 scenario — are all five
    required parts there, and does it actually talk about the threat it's
    supposed to be about?

    structural (all 5 narrative fields present, non-empty) + consistency
    proxy (statement references the threat it narrates). Self-reported
    `assumptions`/`excluded_details` pass through for the reviewer. Flags, never raises."""
    errors = _check_fields(
        scenario, ("scenario_title", "scenario_statement", "business_impact", "operational_impact",
                "risk_statement"))
    statement = str(scenario.get("scenario_statement") or "").lower()
    needle = (threat_name or threat_type or "").lower()
    # Only compare when both sides actually have text — a blank statement/threat name
    # is already reported by _check_fields above, so don't double-flag it here.
    if statement and needle and needle not in statement:
        errors.append("scenario_statement does not reference the threat name/type")
    return {**_result(errors),
            "assumptions": _normalize_str_list(scenario.get("assumptions")),
            "excluded_details": _normalize_str_list(scenario.get("excluded_details"))}

