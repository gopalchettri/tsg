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


def _asset_boundary_pattern(asset_name: str) -> re.Pattern | None:
    """Build a regex that finds the asset name inside text.

    Build one regex pattern for matching/removing an asset name from text, used everywhere
    this needs to happen. Uses lookarounds instead of \\b word boundaries because asset names
    can start or end with non-word characters (like "(PGS)"). A plain substring match would
    also match INSIDE unrelated words — asset name "CIS" once matched inside "decision",
    corrupting text to "Loss of de ion integrity" and poisoning grounding, GenericName, and
    triage downstream."""
    # Handles three cases a plain literal match would miss — each one a real way the asset
    # name used to leak through into GenericName and the shared library:
    #   * trailing punctuation on the name ("ACME Corp.") not matching "ACME Corp systems"
    #   * extra/missing whitespace ("Power  Plant" vs "Power Plant")
    #   * a possessive right after the match ("Citizen Portal's credentials") leaving a
    #     dangling "'s"
    a = (asset_name or "").strip().rstrip(".,;:!")
    if not a:
        return None
    body = r"\s+".join(re.escape(tok) for tok in a.split())
    return re.compile(r"(?<!\w)" + body + r"(?:'s)?(?!\w)", re.IGNORECASE)


def _asset_name_forms(asset_name: str | None) -> list[re.Pattern]:
    """Every way a title can name the asset, longest first: the full name ("Power Generation
    System (PGS)"), the name without its bracketed short form ("Power Generation System") and
    the short form itself ("PGS"). Whole words only, so "PGSX" or "decision" never match."""
    name = (asset_name or "").strip()
    forms = [name]
    short = re.search(r"\(([^()]+)\)\s*$", name)
    if short:
        forms += [name[:short.start()].strip(), short.group(1).strip()]
    pats = (_asset_boundary_pattern(f) for f in dict.fromkeys(forms) if len(f) >= 2)
    return [p for p in pats if p is not None]


#: What sits between a leading asset name and the rest of a title: an em/en dash, colon or bar,
#: or a hyphen with spaces around it ("PGS - loss"). A bare hyphen is part of a word
#: ("PGS-related"). Dashes as escapes, which re reads the same, so nobody mistakes them for "-".
_TITLE_SEPARATOR = r"(?:\s*[\u2014\u2013:|]+\s*|\s+-+\s+)"


def strip_asset_prefix(title: str, asset_name: str | None) -> str:
    """Drop a LEADING asset name and its separator from a scenario title, and start what is left
    with a capital: "Power Generation System (PGS) — loss of telemetry" -> "Loss of telemetry".

    Titles name the impact only; the asset is shown next to them. The prompt asks for that, and
    this makes it true whatever the model writes. A title without such a prefix, or one that is
    nothing but the asset name, is returned unchanged."""
    for pat in _asset_name_forms(asset_name):
        m = re.match(r"\s*(?:" + pat.pattern + r")" + _TITLE_SEPARATOR, title, pat.flags)
        rest = title[m.end():].strip() if m else ""
        if rest:
            return rest[:1].upper() + rest[1:]
    return title


def title_names_asset(title: str, asset_name: str | None) -> bool:
    """Whether a title still names the asset anywhere, in any of its forms."""
    return any(p.search(title) for p in _asset_name_forms(asset_name))


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
    # The title names the IMPACT only — the asset is shown next to it (the statement and risk
    # statement below must still name it). strip_asset_prefix has already removed a leading
    # asset name; one left anywhere else is reported, never rewritten mid-sentence.
    title = str(scenario.get("scenario_title") or "")
    if title.strip() and asset_name and title_names_asset(title, asset_name):
        errors.append(f"scenario_title names the asset ({asset_name}); titles carry only the impact")
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
