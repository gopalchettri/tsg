"""LLM response-shape validation. `parse_json` raises on malformed output so a stage fails LOUDLY;
`validate_scenario` is deterministic-only — structural completeness plus a cheap keyword
consistency proxy, never an LLM-judge call, never a correctness proof.
"""
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


class LLMResponseParseError(Exception):
    """Unparseable JSON or wrong top-level type. Deliberately excludes the raw response text —
    repr(exc) reaches client-visible ErrorMessage/audit/SSE; the caller persists the raw text to
    Prompt_Log instead."""

    def __init__(self, stage: str, expected_type: type):
        self.stage = stage
        self.expected_type = expected_type
        super().__init__(f"{stage}: LLM response failed JSON parsing (expected {expected_type.__name__})")


def parse_json(text: str, *, stage: str, expected_type: type = dict) -> Any:
    """Parse an LLM reply as JSON, stripping a ```-fence. Raises on decode failure or wrong
    top-level type; never returns a default ([R8]: parse failures are terminal stage errors)."""
    t = (text or "").strip()
    if t.startswith("```"):
        t = t.strip("`")
        # Slice from the FIRST brace of EITHER kind. A fenced list-of-objects starts with '[' but
        # its first '{' is *inside* the array — picking that corrupts the parse. No brace at all →
        # leave as-is so json.loads raises cleanly.
        starts = [i for i in (t.find("{"), t.find("[")) if i != -1]
        if starts:
            t = t[min(starts):]
    try:
        parsed = json.loads(t)
    except (json.JSONDecodeError, ValueError, RecursionError) as exc:
        # RecursionError: a pathologically nested reply blows json's recursion limit — it must
        # still surface as the typed terminal error, not escape the [R8] contract.
        raise LLMResponseParseError(stage, expected_type) from exc
    if not isinstance(parsed, expected_type):
        raise LLMResponseParseError(stage, expected_type)
    return parsed


def _check_fields(obj: dict[str, Any], required: tuple[str, ...]) -> list[str]:
    """Missing = absent, None, or blank/whitespace-only."""
    return [f"missing {f}" for f in required if not str(obj.get(f) or "").strip()]


def _result(errors: list[str]) -> dict[str, Any]:
    """The shared ValidationJSON envelope — any error downgrades to warning, never a hard fail."""
    status = ValidationStatus.ok if not errors else ValidationStatus.warning
    return {"validation_status": str(status), "errors": errors}

def _references(needle: str, haystack: str) -> bool:
    """Whole-phrase match, not raw characters inside an unrelated word — a plain `in` passes asset
    name "CAD" against "could cascade into".

    Deliberately NOT `\\b`: that fires only at a word/non-word transition, so `\\bneedle\\b` breaks
    for a needle starting with punctuation (an asset named "(TAAS)") when the preceding haystack
    character is also non-word."""
    n = " ".join(needle.split()).lower()
    if not n:
        return False
    h = " ".join(haystack.split()).lower()
    return re.search(rf"(?<![a-z0-9]){re.escape(n)}(?![a-z0-9])", h) is not None


def _mentions(needle: str, haystack: str) -> bool:
    """Consistency proxy: does `haystack` share >= ~1/3 (min 1) of `needle`'s significant tokens?

    Whole-phrase matching false-warns on 100% of on-topic scenarios — paraphrased prose never
    repeats a full formal name verbatim. Significant = lowercased alphanumeric runs of length >= 3,
    not stopwords, not pure digits; an all-stopword needle passes.

    Two refinements stop a same-shaped SIBLING entity matching: a parenthetical short form
    ("Power Generation System (PGS)") short-circuits True rather than being diluted to 1-of-4
    tokens, and every purely-numeric token must match EXACTLY, or "Substation Gateway 4" and
    "Substation Gateway 7" read as one entity."""
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
    """Always a list of strings. Pass-through informational data — never affects validation_status."""
    if isinstance(raw, str):
        return [raw]
    if isinstance(raw, list):
        return [x for x in raw if isinstance(x, str)]
    return []


#: Advisory identifiers the prompt lets the model cite VERBATIM from the injected intel block.
#: Deliberately narrow — only shapes that are unambiguously advisory ids, so ordinary prose can
#: never look like a citation.
_ADVISORY_ID_RX = re.compile(r"\b(?:CVE-\d{4}-\d{4,7}|ICSA(?:MA)?-\d{2}-\d{3}-\d{2})\b", re.I)


def _uncited_advisory_ids(scenario: dict[str, Any], injected_ids: set[str] | None) -> list[str]:
    """Advisory ids the scenario cites that were NOT in the block the model was given — an
    invented or mis-copied CVE would otherwise be served to reviewers as real evidence.

    Compared casefolded (a case variant is a real citation). `injected_ids=None` means the caller
    doesn't know what was injected, so the check is skipped rather than flagging everything."""
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
    """Structural check (title/statement/risk_statement present) plus a consistency proxy: the
    statement references its threat, title and statement reference the asset, risk_statement
    references the asset and critical service. Flags, never raises.

    The proxy is TOKEN OVERLAP via `_mentions`, not whole-phrase containment. `critical_service` is
    a list and passing ANY one suffices — the model writes about one threat, not every service.

    Redaction is one-directional: prompts.py redacts inbound context, but the LLM's OUTPUT is
    persisted and served as-is. A model echoing something sensitive back is not caught here or by
    any later stage. Documented residual risk."""
    errors = _check_fields(
        scenario, ("scenario_title", "scenario_statement", "risk_statement"))
    statement = str(scenario.get("scenario_statement") or "")
    needle = threat_name or threat_type or ""
    # Only compare when both sides have text — a blank field is already reported by _check_fields,
    # so don't double-flag it. Same guard on every check below.
    if statement.strip() and needle.strip() and not _mentions(needle, statement):
        errors.append(f"scenario_statement does not reference the threat name/type ({needle})")
    title = str(scenario.get("scenario_title") or "")
    if title.strip() and asset_name and not _mentions(asset_name, title):
        errors.append(f"scenario_title does not reference the asset ({asset_name})")
    if statement.strip() and asset_name and not _mentions(asset_name, statement):
        errors.append(f"scenario_statement does not reference the asset ({asset_name})")
    # a blank critical_service is a real, allowed asset state — not every asset has one
    risk_statement = str(scenario.get("risk_statement") or "")
    if risk_statement.strip() and asset_name and not _mentions(asset_name, risk_statement):
        errors.append(f"risk_statement does not reference the asset ({asset_name})")
    if risk_statement.strip() and critical_service and not any(_mentions(cs, risk_statement) for cs in critical_service):
        errors.append(f"risk_statement does not reference the critical service ({', '.join(critical_service)})")
    # Citation discipline: the prompt permits citing an advisory ONLY from the injected block.
    invented = _uncited_advisory_ids(scenario, injected_intel_ids)
    if invented:
        errors.append("cites advisory identifiers that were not provided in the intel block "
                    f"({', '.join(invented)})")
    return {**_result(errors),
            "assumptions": _normalize_str_list(scenario.get("assumptions")),
            "excluded_details": _normalize_str_list(scenario.get("excluded_details"))}
