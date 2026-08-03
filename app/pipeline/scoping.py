"""Threat scoping — deterministic rule evaluation.

Base score + grounding-confidence weight, then the `Config_Threat_Rule` engine: `tech_gate` rules
are a hard include/exclude (a failed gate → `Selected = 0`, the Reason names the gate);
`relevance_flag`/`relevance_context_value` rules add weights to `Score`. RuleKey→field resolution
goes through the fixed `_RULE_KEY_FIELDS` allowlist — an unknown key, an unknown rule family, or
an absent context field means the rule has NO effect and is logged (never silently false). Every
rule that fires is recorded in `Scored.factors` → `Scoped_Threat.FactorsJSON`. The selection
cutoff (score threshold / top-N) comes from config, not constants.

Same inputs → same ranking. This governs ranking a FIXED list of already-identified threats, not
whether the LLM proposes the same threats twice.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from app.core.enums import GroundingStatus, ScopingRejection, ThreatRuleType
from app.core.logging import get_logger

log = get_logger(__name__)

BASE_SCORE = 50.0
# unverified (novel/unmatched-to-library) threats must land ABOVE the scoping_score_threshold
# cutoff (default 55) or a curator never sees the ones they haven't catalogued yet: 15.0 puts them
# at 65, below a real library match (verified 70) but still comfortably surfaced. Grounding
# confidence ALONE must never reject a threat — only a negative rule delta may take a score under
# the cutoff, so BASE_SCORE + min(weights) stays above it by construction.
_CONFIDENCE_WEIGHT = {GroundingStatus.verified: 20.0, GroundingStatus.unverified: 15.0}
_DEFAULT_RULE_WEIGHT = 10.0  # relevance_* delta when the rule's Metadata carries no {"weight": N}

# The fixed RuleKey → context-field allowlist: RuleKey → (subsystem field it reads, default
# expected value used when RuleValue is NULL; None = plain truthy check). Extending it is one line
# per key + curator sign-off on the mapping — but check gather_asset_details actually PRODUCES the
# field first: internet_facing / exposure_level / accessibility_channel / hosting_environment /
# data_residency were removed 2026-07-12 for exactly that reason. Re-adding a key the context
# never carries fails SILENTLY (an unknown key logs and continues at _apply_rules; an absent
# field is a no-op), so the rule would just never fire. See TSG_Gap_Analysis.md.
#
# asset_type resolves to text, so _matches() takes its case-insensitive TEXT branch, not numeric.
_RULE_KEY_FIELDS: dict[str, tuple[str, str | None]] = {
    "criticality": ("criticality", None),
    "subsystem_name": ("name", None),
    "asset_type": ("asset_type", None),
    "past_incidents": ("past_incidents", None),
}


@dataclass
class Scored:
    """Scored/ranked result for one threat: score, rank, whether it made the cut, why, and which
    rules contributed."""

    threat_id: str
    score: float
    rank: int
    selected: bool
    reason: str
    # `reason` is prose for the reviewer; `rejection` is the same fact for code. Kept adjacent
    # because they are always assigned together — split them and they drift.
    rejection: ScopingRejection | None = None  # None ⟺ selected; persisted to RejectionKind
    factors: list[dict] = field(default_factory=list)  # every fired rule: {key, family, delta[, gate]}


def _rule_weight(rule: dict) -> float | None:
    """Metadata `{"weight": N}` override. Curator-entered JSON is a trust boundary: log, never
    crash, never guess.
      * absent, or `{"weight": null}` → default;
      * a number or numeric string like "15" → that weight (0 is a legal choice);
      * a bool, any other non-numeric value, or unparseable JSON → None, and the caller skips the
        rule — firing with a guessed weight is a silent effect the curator never chose."""
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
    """No expected value → plain truthy check. Otherwise numeric-tolerant equality first
    ("05" / "5.0" / 5 all match — curator-typed text vs int/str context fields), falling back to
    case-insensitive string comparison. Booleans never take the float branch: True matches only
    "1"/"true", False only "0"/"false". A curator-typed "NaN" fails the numeric branch (IEEE754)
    and falls to text comparison — intended."""
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


def _apply_rules(threat: dict, subsystems: list[dict] | None, rules_by_type: dict) -> tuple[float, bool, list[str], list[dict]]:
    """Evaluate every rule for this threat's grounded type. The asset is threat-modeled as a
    whole, so a subsystem-keyed rule fires if ANY supporting system matches: a tech_gate passes
    when any does, a relevance_* weight is added once. Returns (score delta, selected, failed gate
    keys, fired factors). A threat with no `threat_type_id` has no type to key rules on and is
    untouched. `criticality` is the asset's own value, copied onto every supporting system by
    context.py, so an any-match check reads it correctly."""
    delta, selected, gate_failures, factors = 0.0, True, [], []
    subs = subsystems or []
    for rule in rules_by_type.get(threat.get("threat_type_id"), []):
        key = rule["RuleKey"]
        mapping = _RULE_KEY_FIELDS.get(key)
        if mapping is None:  # unknown key → no effect, logged — never silently false
            log.warning("scoping.rule_key_unknown", rule_key=key)
            continue
        fld, default_expected = mapping
        # value-presence, NOT key-presence: context.py always emits every rule-keyable key (value
        # None when unresolved), so `fld in s` is always True and would make a tech_gate keyed on
        # an all-None field fail CLOSED, silently excluding the threat. `is not None` keeps a
        # curator's explicit "" or 0 evaluated while treating an unresolved field as absent.
        present = [s for s in subs if s.get(fld) is not None]
        if not present:  # field unresolved (None)/absent on every supporting system → no-effect rule
            log.warning("scoping.rule_field_absent", rule_key=key, field=fld)
            continue
        # "" is a real curator value (match-empty), NOT "fall back to the default" — only
        # a true NULL RuleValue uses the allowlist entry's default expected value.
        rule_value = rule.get("RuleValue")
        expected = rule_value if rule_value is not None else default_expected
        matched = any(_matches(s.get(fld), expected) for s in present)  # fires if ANY supporting system matches
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


def _scoring_reason(gate_failures: list[str], grounding_status: Any) -> tuple[str, ScopingRejection | None]:
    """Reason records the gate on exclusion, else the grounding basis. Returns the prose AND the
    machine-readable kind, together — never one without the other."""
    if gate_failures:
        return f"tech_gate:{','.join(gate_failures)} failed", ScopingRejection.tech_gate
    return f"grounding={grounding_status}", None


def _apply_selection_cutoffs(selected: bool, score: float, reason: str,
                            rejection: ScopingRejection | None, kept: int, *,
                            score_threshold: float | None, top_n: int | None,
                            ) -> tuple[bool, str, ScopingRejection | None, int]:
    """The two config-driven selection cutoffs, applied in rank order. top_n only counts threats
    still selected at this point — ones already excluded by the gate or threshold don't use up a
    slot. Returns the possibly-updated (selected, reason, rejection) plus the running `kept` count.

    Only `top_n_cutoff` is re-servable by "generate next set": a below-threshold threat re-scores
    below threshold every time, whereas a top-N casualty is re-selected the moment it is scored in
    target mode. That distinction lives in the KIND, never in the wording of `reason`."""
    if selected and score_threshold is not None and score < score_threshold:
        selected, reason = False, f"below score threshold ({score_threshold})"
        rejection = ScopingRejection.below_threshold
    if selected and top_n is not None:
        kept += 1
        if kept > top_n:
            selected, reason = False, f"beyond top-{top_n} cutoff"
            rejection = ScopingRejection.top_n_cutoff
    return selected, reason, rejection, kept


def score_threats(threats: list[dict[str, Any]], *, subsystems: list[dict] | None = None,
                rules: list[dict] | None = None, score_threshold: float | None = None,
                top_n: int | None = None) -> list[Scored]:
    """Score and rank the asset's identified threats and decide which move forward to a written
    scenario. Deterministic: same inputs → same ranking. Called with only `threats` (no rules, no
    cutoff) it is base + grounding weight with everything selected."""
    rules_by_type: dict[int, list[dict]] = {}
    for r in rules or []:
        rules_by_type.setdefault(r["ThreatTypeID"], []).append(r)

    evaluated = []
    for t in threats:
        score = BASE_SCORE + _CONFIDENCE_WEIGHT.get(GroundingStatus(t["grounding_status"]), 0.0)
        delta, selected, gate_failures, factors = _apply_rules(t, subsystems, rules_by_type)
        score += delta
        reason, rejection = _scoring_reason(gate_failures, t["grounding_status"])
        evaluated.append((t["threat_id"], score, selected, reason, rejection, factors))

    evaluated.sort(key=lambda x: (-x[1], x[0]))  # score desc, id asc — stable
    out: list[Scored] = []
    kept = 0  # fresh per call — cutoff state never crosses subsystems/invocations
    for rank, (tid, score, selected, reason, rejection, factors) in enumerate(evaluated, start=1):
        selected, reason, rejection, kept = _apply_selection_cutoffs(
            selected, score, reason, rejection, kept, score_threshold=score_threshold, top_n=top_n)
        out.append(Scored(threat_id=tid, score=score, rank=rank, selected=selected, reason=reason,
                        rejection=rejection, factors=factors))
    return out
