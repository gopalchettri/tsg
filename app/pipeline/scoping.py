"""In plain English: decides which of the threats the AI found are worth
writing a full scenario for, and in what order — using a scoring system plus
any rules an admin/curator has set up.

Threat scoping  — deterministic rule evaluation.

Base score + grounding-confidence weight, then the `Config_Threat_Rule` engine:
`tech_gate` rules are a hard include/exclude (a failed gate → `Selected = 0`, the
Reason names the gate); `relevance_flag`/`relevance_context_value` rules add
weights to `Score`. RuleKey→field resolution goes through the fixed
`_RULE_KEY_FIELDS` allowlist — an unknown key, an unknown rule family, or an
absent context field means the rule has NO effect and is logged (§5.4 step 1:
never silently false). Every rule that fires is recorded in `Scored.factors` →
`Scoped_Threat.FactorsJSON` (provenance, §11). The selection cutoff (score
threshold / top-N) comes from config (§5.4 step 3), not constants — both now
default ON (55.0 / 5, `Settings.scoping_score_threshold`/`scoping_top_n`); set
either to None there to go back to no cutoff. Same inputs → same ranking
(acceptance: test_scoping_deterministic, test_tech_gate_excludes) — this
governs ranking a FIXED list of already-identified threats, not whether the
LLM proposes the same threats twice (see TSG_SDD.md §9.1b for that).
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from app.core.enums import GroundingStatus, ThreatRuleType
from app.core.logging import get_logger

log = get_logger(__name__)

BASE_SCORE = 50.0
# flagged (novel/unmatched-to-library) threats are NOT nothing — they're the ones a curator
# hasn't catalogued yet. flagged=0.0 previously left them at exactly BASE_SCORE (50), which the
# scoping_score_threshold cutoff (55.0, below) would silently exclude outright. 15.0 keeps them
# ranked below a real library match (grounded=70, confirm=60) but past that threshold (65), so
# they still surface for a curator to review rather than vanishing before anyone sees them.
_CONFIDENCE_WEIGHT = {GroundingStatus.grounded: 20.0, GroundingStatus.confirm: 10.0, GroundingStatus.flagged: 15.0}
_DEFAULT_RULE_WEIGHT = 10.0  # relevance_* delta when the rule's Metadata carries no {"weight": N}

# step 1 — the fixed RuleKey → context-field allowlist. Each entry maps a
# RuleKey to (subsystem field it reads, default expected value used when RuleValue is
# NULL; None = plain truthy check). Keys removed 2026-07-12: internet_facing/
# exposure_level/accessibility_channel/hosting_environment/data_residency — the
# onboarding_supporting_systems columns they read (accessability_channel,
# hosting_location, data_residency_restrictions) don't exist on the real platform
# table, so gather_asset_details no longer produces them (see
# TSG_Gap_Analysis.md's table cross-check entry). Extending this map is one line
# per key + curator sign-off on the RuleKey→field mapping.
# Note: asset_type's value is now resolved text (ctm_scan_category.name,
# Part E), so _matches() takes its case-insensitive TEXT branch here, not the numeric one.
_RULE_KEY_FIELDS: dict[str, tuple[str, str | None]] = {
    "criticality": ("criticality", None),
    "subsystem_name": ("name", None),
    "asset_type": ("asset_type", None),
    "past_incidents": ("past_incidents", None),
}


@dataclass
class Scored:
    """In plain English: the scored/ranked result for one threat — its score,
    rank, whether it made the cut, why, and which rules contributed."""

    threat_id: str
    score: float
    rank: int
    selected: bool
    reason: str
    factors: list[dict] = field(default_factory=list)  # every fired rule: {key, family, delta[, gate]} (§5.4 step 4)


def _rule_weight(rule: dict) -> float | None:
    """In plain English: works out how many bonus points a matching rule
    should add, while safely handling a curator's badly-typed settings.

    Metadata `{"weight": N}` override; the complete discipline (curator-entered
    JSON is a trust boundary: log, never crash, never guess):
      * Metadata absent, or `{"weight": null}` (JSON null = no override) → default;
      * a number, or a numeric string like "15" → that weight (0 is a legal choice);
      * a bool, any other non-numeric value, or unparseable JSON → None, and the
        caller skips the rule entirely — firing with a guessed weight would be a
        silent effect the curator never chose (same no-effect rule as §5.4 step 1)."""
    meta = rule.get("Metadata")
    if not meta:
        return _DEFAULT_RULE_WEIGHT
    try:
        weight = json.loads(meta).get("weight")
    except (ValueError, AttributeError):
        log.warning("scoping.rule_metadata_invalid", rule_key=rule.get("RuleKey"))
        return None
    if weight is None:
        return _DEFAULT_RULE_WEIGHT
    if isinstance(weight, bool):  # bool is not a weight — no-effect, not a guess of 1.0/0.0
        log.warning("scoping.rule_metadata_invalid", rule_key=rule.get("RuleKey"))
        return None
    try:
        return float(weight)
    except (TypeError, ValueError):
        log.warning("scoping.rule_metadata_invalid", rule_key=rule.get("RuleKey"))
        return None


def _matches(value: Any, expected: str | None) -> bool:
    """In plain English: checks whether a subsystem's real value matches what
    a rule expects, being flexible about numbers written as text.

    No expected value → plain truthy check. Otherwise numeric-tolerant equality
    first ("05" / "5.0" / 5 all match — curator-typed text vs int/str context fields),
    falling back to case-insensitive string comparison. Booleans never take the
    float-coercion branch; instead a real bool accepts the equivalent canonical
    spellings (case-insensitive, stripped): True matches "1" or "true", False matches
    "0" or "false" — any other expected string never matches a bool. A curator-typed
    "NaN" never matches on the numeric branch (IEEE754), then falls to text
    comparison — intended. Pure function of its inputs — deterministic either way."""
    if expected is None:
        return bool(value)
    if isinstance(value, bool):  # bools never take the float branch — canonical spellings only
        exp = expected.strip().lower()
        return exp in ("1", "true") if value else exp in ("0", "false")
    try:
        return float(value) == float(expected)
    except (TypeError, ValueError):
        pass
    return str(value).strip().lower() == expected.strip().lower()


def _apply_rules(threat: dict, subsystem: dict | None, rules_by_type: dict) -> tuple[float, bool, list[str], list[dict]]:
    """In plain English: runs every relevant rule against one threat, and
    works out its bonus score plus whether it should be excluded entirely.

    Evaluate every rule for this threat's grounded type (§5.4 step 2). Returns
    (score delta, selected, failed gate keys, fired factors). A threat with no
    `threat_type_id` (ungrounded) has no type to key rules on — untouched."""
    delta, selected, gate_failures, factors = 0.0, True, [], []
    for rule in rules_by_type.get(threat.get("threat_type_id"), []):
        key = rule["RuleKey"]
        mapping = _RULE_KEY_FIELDS.get(key)
        if mapping is None:  # unknown key → no effect, logged — never silently false (§5.4 step 1)
            log.warning("scoping.rule_key_unknown", rule_key=key)
            continue
        fld, default_expected = mapping
        if subsystem is None or fld not in subsystem:  # absent context field → same no-effect rule
            log.warning("scoping.rule_field_absent", rule_key=key, field=fld)
            continue
        # "" is a real curator value (match-empty), NOT "fall back to the default" — only
        # a true NULL RuleValue uses the allowlist entry's default expected value.
        rule_value = rule.get("RuleValue")
        matched = _matches(subsystem.get(fld), rule_value if rule_value is not None else default_expected)
        family = rule["RuleType"]
        if family == ThreatRuleType.tech_gate:
            if not matched:
                selected = False
                gate_failures.append(key)
            factors.append({"key": key, "family": str(ThreatRuleType.tech_gate), "delta": 0.0,
                            "gate": "passed" if matched else "failed"})
        elif family in (ThreatRuleType.relevance_flag, ThreatRuleType.relevance_context_value):
            if matched:
                weight = _rule_weight(rule)
                if weight is None:  # malformed Metadata → rule skipped (logged in _rule_weight)
                    continue
                delta += weight
                factors.append({"key": key, "family": str(family), "delta": weight})
        else:  # unrecognized family → same no-effect discipline as an unknown key
            log.warning("scoping.rule_type_unknown", rule_type=str(family), rule_key=key)
    return delta, selected, gate_failures, factors


def _scoring_reason(gate_failures: list[str], grounding_status: Any) -> str:
    """In plain English: builds the human-readable reason string for one
    threat's score — which gate it failed, or (if none) what grounding basis
    the score was built on.

    Reason records the gate on exclusion (§5.4 step 2), else the grounding basis."""
    if gate_failures:
        return f"tech_gate:{','.join(gate_failures)} failed"
    return f"grounding={grounding_status}"


def _apply_selection_cutoffs(selected: bool, score: float, reason: str, kept: int, *,
                            score_threshold: float | None, top_n: int | None) -> tuple[bool, str, int]:
    """In plain English: enforces the two independent, config-driven selection
    cutoffs (score-threshold and top-N) against one already-ranked threat.

    Config-driven selection cutoff (§5.4 step 3) — applied in rank order, deterministic.
    top_n only counts threats that are still selected at this point — ones already
    excluded by the gate or threshold don't use up a slot. Returns the possibly-updated
    (selected, reason) plus the running `kept` count for the caller's next threat."""
    if selected and score_threshold is not None and score < score_threshold:
        selected, reason = False, f"below score threshold ({score_threshold})"
    if selected and top_n is not None:
        kept += 1
        if kept > top_n:
            selected, reason = False, f"beyond top-{top_n} cutoff"
    return selected, reason, kept


def score_threats(threats: list[dict[str, Any]], *, subsystem: dict | None = None,
                rules: list[dict] | None = None, score_threshold: float | None = None,
                top_n: int | None = None) -> list[Scored]:
    """In plain English: the main function here — takes the threats for one
    subsystem, scores and ranks them, and decides which ones move forward to
    get a written scenario.

    Deterministic: same inputs → same ranking (acceptance: test_scoping_deterministic).
    Called with only `threats` (no rules, no cutoff) this is exactly the pre-R12
    behavior: base + grounding weight, everything selected."""
    # Bucket the curator's rules by threat type, so each threat below only gets
    # checked against the rules that actually apply to its type.
    rules_by_type: dict[int, list[dict]] = {}
    for r in rules or []:
        rules_by_type.setdefault(r["ThreatTypeID"], []).append(r)

    # Score every threat: start from base + grounding-confidence weight, then
    # layer on whatever the config rules add or exclude.
    evaluated = []
    for t in threats:
        score = BASE_SCORE + _CONFIDENCE_WEIGHT.get(GroundingStatus(t["grounding_status"]), 0.0)
        delta, selected, gate_failures, factors = _apply_rules(t, subsystem, rules_by_type)
        score += delta
        reason = _scoring_reason(gate_failures, t["grounding_status"])
        evaluated.append((t["threat_id"], score, selected, reason, factors))

    evaluated.sort(key=lambda x: (-x[1], x[0]))  # score desc, id asc — stable (§5.4 step 3)
    out: list[Scored] = []
    kept = 0  # fresh per call — cutoff state never crosses subsystems/invocations
    for rank, (tid, score, selected, reason, factors) in enumerate(evaluated, start=1):
        selected, reason, kept = _apply_selection_cutoffs(
            selected, score, reason, kept, score_threshold=score_threshold, top_n=top_n)
        out.append(Scored(threat_id=tid, score=score, rank=rank, selected=selected, reason=reason, factors=factors))
    return out
