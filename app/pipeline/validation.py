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
import math
import re
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


def _references(needle: str, haystack: str) -> bool:
    """Whether `needle` appears in `haystack` as a whole phrase, not just as raw characters
    embedded inside an unrelated word. A naive `needle in haystack` check lets a short/common
    needle silently "match" text that never actually mentions it — e.g. asset name "CAD" is a
    substring of "cascade", so a risk_statement that never mentions the CAD asset at all but
    happens to say "...could cascade into..." would wrongly pass. Confirmed live during review:
    `'cad' in 'could cascade into downstream failures'` is True.

    Normalizes whitespace on both sides first (an asset name stored with a double space
    shouldn't false-flag prose that naturally renders it with a single space), then requires the
    match not be immediately flanked by another letter/digit in the HAYSTACK. Deliberately NOT
    `\\b` — `\\b` only fires at a word/non-word transition, so `\\bneedle\\b` breaks for a needle
    that itself starts/ends with punctuation (e.g. an asset literally named "(TAAS)"): the `\\b`
    right before "(" fails when the preceding haystack character is also non-word (a space).
    Checking only the haystack's neighboring characters — regardless of the needle's own edge
    character — doesn't have that gap."""
    n = " ".join(needle.split()).lower()
    if not n:
        return False
    h = " ".join(haystack.split()).lower()
    return re.search(rf"(?<![a-z0-9]){re.escape(n)}(?![a-z0-9])", h) is not None


# Common words that carry no topical signal — dropped before token overlap so a needle like
# "Compromised OT supply chain or hardware" isn't "matched" just because the haystack also says "or".
_STOPWORDS = frozenset({"the", "and", "or", "of", "to", "a", "an", "for", "with",
                        "in", "on", "by", "at", "from", "that", "this"})


def _mentions(needle: str, haystack: str) -> bool:
    """Loosened consistency proxy: does `haystack` share at least ~1/3 (minimum 1) of `needle`'s
    significant tokens? Replaces the old whole-phrase `_references(needle, haystack)` for the
    scenario checks — paraphrased prose never repeats a full formal threat/asset name verbatim, so
    the strict phrase check false-warned on 100% of on-topic scenarios. Significant tokens are
    lowercased alphanumeric runs of length >= 3 that aren't common stopwords; an all-stopword/empty
    needle has nothing meaningful to check and passes (True). Each token is matched with the existing
    word-boundary `_references` so a short token still can't match inside an unrelated word."""
    tokens = [t for t in re.findall(r"[a-z0-9]+", needle.lower())
            if len(t) >= 3 and t not in _STOPWORDS]
    if not tokens:
        return True
    hits = sum(1 for t in tokens if _references(t, haystack))
    return hits >= max(1, math.ceil(len(tokens) / 3))


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


def validate_scenario(scenario: dict[str, Any], threat_type: str | None, threat_name: str | None,
                    asset_name: str | None = None, critical_service: list[str] | None = None) -> dict[str, Any]:
    """ sanity-checks the Stage-2 scenario — are the three
    required parts (scenario_title, scenario_statement, risk_statement) there,
    and does it actually talk about the threat it's supposed to be about?

    structural (scenario_title, scenario_statement, risk_statement present,
    non-empty — the three fields scenario_prompt actually produces) + consistency
    proxy (statement references the threat it narrates; risk_statement references the asset
    and critical service, per the prompt's own "threat + asset + critical service + impact"
    formula). The consistency proxy is now TOKEN OVERLAP (~1/3 of the name/type's significant
    tokens appear, via `_mentions`), NOT whole-phrase containment — paraphrased on-topic prose
    never repeats a full formal name verbatim, so the old phrase check warned on everything.
    Self-reported `assumptions`/`excluded_details` pass through for the reviewer.
    `asset_name`/`critical_service` default to None so existing callers that don't have them
    handy keep working unchanged — the check simply doesn't run for them. Flags, never raises.

    `critical_service` is a list (an asset can legitimately link to more than one service via
    ctm_scan_entity_bu — see context.py::_load_asset) — the check passes if the risk_statement
    references ANY one of them, not all: the model is writing about one specific threat, not
    obligated to enumerate every service the asset happens to support.

    Redaction is one-directional: prompts.py redacts inbound context before it reaches the
    LLM, but this function does not scrub the LLM's OUTPUT — scenario/threat text returned
    here is persisted and served to reviewers as-is. A model that echoes something sensitive
    back (e.g. from context it was given) is not caught by validate_scenario or by any later
    stage. Documented residual risk, not a gap this function is meant to close."""
    errors = _check_fields(
        scenario, ("scenario_title", "scenario_statement", "risk_statement"))
    statement = str(scenario.get("scenario_statement") or "")
    needle = threat_name or threat_type or ""
    # Only compare when both sides actually have text — a blank statement/threat name
    # is already reported by _check_fields above, so don't double-flag it here.
    if statement.strip() and needle.strip() and not _mentions(needle, statement):
        errors.append(f"scenario_statement does not reference the threat name/type ({needle})")
    risk_statement = str(scenario.get("risk_statement") or "")
    # Same "only compare when both sides have text" guard as above — an empty risk_statement is
    # already reported by _check_fields, and a blank critical_service is a real, allowed asset
    # state (not every asset has one configured), not something to false-flag here.
    if risk_statement.strip() and asset_name and not _mentions(asset_name, risk_statement):
        errors.append(f"risk_statement does not reference the asset ({asset_name})")
    if risk_statement.strip() and critical_service and not any(_mentions(cs, risk_statement) for cs in critical_service):
        errors.append(f"risk_statement does not reference the critical service ({', '.join(critical_service)})")
    return {**_result(errors),
            "assumptions": _normalize_str_list(scenario.get("assumptions")),
            "excluded_details": _normalize_str_list(scenario.get("excluded_details"))}

