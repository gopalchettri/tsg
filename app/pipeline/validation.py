"""Validate LLM JSON responses and generated scenario fields without another LLM call."""
from __future__ import annotations

import json
import math
import re
from typing import Any

from app.core.enums import ValidationStatus

# Dropped before token overlap so a needle like "Compromised OT supply chain or hardware" isn't
# "matched" just because the haystack also says "or".
_STOPWORDS = frozenset({"the", "and", "or", "of", "to", "a", "an", "for", "with",
                        "in", "on", "by", "at", "from", "that", "this"})

# Find advisory IDs in generated scenario text.
# Matches examples: CVE-2024-1234, ICSA-24-123-45, and ICSAMA-24-123-45.
# Ignores normal words such as "security" and invalid IDs such as CVE-24-123 or ICSA-24-12-3.
_ADVISORY_ID_RX = re.compile(r"\b(?:CVE-\d{4}-\d{4,7}|ICSA(?:MA)?-\d{2}-\d{3}-\d{2})\b", re.IGNORECASE)



class LLMResponseParseError(Exception):
    """Raised when an LLM response is invalid JSON or has the wrong top-level type."""

    def __init__(self, stage: str, expected_type: type):
        self.stage = stage
        self.expected_type = expected_type
        super().__init__(f"{stage}: LLM response failed JSON parsing (expected {expected_type.__name__})")


def parse_json(text: str, *, stage: str, expected_type: type = dict) -> Any:
    """Parse an LLM reply as JSON and require the requested top-level type.

    Removes Markdown code fences and raises ``LLMResponseParseError`` for invalid JSON,
    deeply nested JSON, or an unexpected top-level type.
    """
    t = (text or "").strip()
    if t.startswith("```"):
        t = t.strip("`")
        # Start at the first object or array delimiter. This preserves fenced JSON arrays.
        starts = [i for i in (t.find("{"), t.find("[")) if i != -1]
        if starts:
            t = t[min(starts):]
    try:
        parsed = json.loads(t)
    except (json.JSONDecodeError, ValueError, RecursionError) as exc:
        # Treat excessive nesting as the same parse failure as invalid JSON.
        raise LLMResponseParseError(stage, expected_type) from exc
    if not isinstance(parsed, expected_type):
        raise LLMResponseParseError(stage, expected_type)
    return parsed


def _check_fields(obj: dict[str, Any], required: tuple[str, ...]) -> list[str]:
    """Return an error for each required field that is absent or blank."""
    return [f"missing {f}" for f in required if not str(obj.get(f) or "").strip()]


def _result(errors: list[str]) -> dict[str, Any]:
    """Build the validation result; errors produce a warning status."""
    status = ValidationStatus.ok if not errors else ValidationStatus.warning
    return {"validation_status": str(status), "errors": errors}

def _references(needle: str, haystack: str) -> bool:
    """Return whether ``haystack`` contains ``needle`` as a complete phrase.

    Matching ignores case and repeated whitespace, and requires letters or digits to stop
    the phrase from matching inside a larger word.
    """
    n = " ".join(needle.split()).lower()
    if not n:
        return False
    h = " ".join(haystack.split()).lower()
    return re.search(rf"(?<![a-z0-9]){re.escape(n)}(?![a-z0-9])", h) is not None


def _mentions(needle: str, haystack: str) -> bool:
    """Return whether ``haystack`` contains enough meaningful parts of ``needle``.

    At least one third of the non-stopword tokens must match, with at least one match required.
    Parenthetical short forms match directly, and number tokens must match exactly.
    """
    raw = re.findall(r"[a-z0-9]+", needle.lower())
    short_form = re.search(r"[(\"']([a-z0-9]+)[)\"']", needle.lower())
    if short_form and _references(short_form.group(1), haystack):
        return True
    digits = [t for t in raw if t.isdigit()]
    if digits and not all(_references(d, haystack) for d in digits):
        return False
    tokens = [t for t in raw if len(t) >= 3 and t not in _STOPWORDS and not t.isdigit()]
    if not tokens:
        return True
    hits = sum(1 for t in tokens if _references(t, haystack))
    return hits >= max(1, math.ceil(len(tokens) / 3))


def _normalize_str_list(raw: Any) -> list[str]:
    """Return a string as a one-item list, or keep only strings from a list."""
    if isinstance(raw, str):
        return [raw]
    if isinstance(raw, list):
        return [x for x in raw if isinstance(x, str)]
    return []

def _uncited_advisory_ids(scenario: dict[str, Any], injected_ids: set[str] | None) -> list[str]:
    """Return advisory IDs cited by the scenario but missing from the injected intel IDs.

    Comparison ignores case. If the injected ID set is ``None``, return no errors because
    the available reference list is unknown.
    """
    if injected_ids is None:
        return []
    known = {i.casefold() for i in injected_ids}
    text = " ".join(str(scenario.get(f) or "") for f in
                    ("scenario_title", "scenario_statement", "risk_statement"))
    seen: dict[str, str] = {}
    for raw in _ADVISORY_ID_RX.findall(text):
        seen.setdefault(raw.casefold(), raw)
    return sorted(v for k, v in seen.items() if k not in known)


def validate_scenario(scenario: dict[str, Any], threat_type: str | None, threat_name: str | None,
                    asset_name: str | None = None, critical_service: list[str] | None = None,
                    injected_intel_ids: set[str] | None = None) -> dict[str, Any]:
    """Check required fields, threat and asset references, and advisory citations.

    Returns a result with ``ok`` or ``warning`` status and an error list; it never raises.
    Reference checks use token overlap. Any one matching value in ``critical_service`` is enough.
    ``assumptions`` and ``excluded_details`` are returned as lists of strings.
    """
    errors = _check_fields(
        scenario, ("scenario_title", "scenario_statement", "risk_statement"))
    statement = str(scenario.get("scenario_statement") or "")
    needle = threat_name or threat_type or ""
    # Skip reference checks for blank fields already reported by _check_fields.
    if statement.strip() and needle.strip() and not _mentions(needle, statement):
        errors.append(f"scenario_statement does not reference the threat name/type ({needle})")
    title = str(scenario.get("scenario_title") or "")
    if title.strip() and asset_name and not _mentions(asset_name, title):
        errors.append(f"scenario_title does not reference the asset ({asset_name})")
    if statement.strip() and asset_name and not _mentions(asset_name, statement):
        errors.append(f"scenario_statement does not reference the asset ({asset_name})")
    # An asset may have no critical service, so check this field only when provided.
    risk_statement = str(scenario.get("risk_statement") or "")
    if risk_statement.strip() and asset_name and not _mentions(asset_name, risk_statement):
        errors.append(f"risk_statement does not reference the asset ({asset_name})")
    if risk_statement.strip() and critical_service and not any(_mentions(cs, risk_statement) for cs in critical_service):
        errors.append(f"risk_statement does not reference the critical service ({', '.join(critical_service)})")
    # Reject advisory IDs that were not included in the model's input.
    invented = _uncited_advisory_ids(scenario, injected_intel_ids)
    if invented:
        errors.append("cites advisory identifiers that were not provided in the intel block "
                    f"({', '.join(invented)})")
    return {**_result(errors),
            "assumptions": _normalize_str_list(scenario.get("assumptions")),
            "excluded_details": _normalize_str_list(scenario.get("excluded_details"))}
