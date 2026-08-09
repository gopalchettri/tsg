"""Threat scoping — deterministic rule evaluation.

Base score + grounding-confidence weight, then the `Config_Threat_Rule` engine: `tech_gate` is a
hard include/exclude (failed → `Selected = 0`), `relevance_flag`/`relevance_context_value` add
weights. RuleKey→field resolution goes through the fixed `_RULE_KEY_FIELDS` allowlist — an unknown
key, unknown family, or absent context field means NO effect and is logged, never silently false.
Every fired rule lands in `Scored.factors` → `Scoped_Threat.FactorsJSON`.

Same inputs → same ranking.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from app.core.enums import GroundingStatus, ScopingRejection, SelectionReason, ThreatRuleType
from app.core.logging import get_logger

log = get_logger(__name__)

# base_score and default_rule_weight arrive as score_threats parameters, never module literals, so
# a Config_Tuning session snapshot can override them per assessment.
#
# unverified (novel) threats must land ABOVE scoping_score_threshold (default 55) or a curator
# never sees what they haven't catalogued: 15.0 puts them at 65, below a real library match
# (verified 70) but comfortably surfaced. Grounding confidence ALONE must never reject a threat —
# only a negative rule delta may take a score under the cutoff.
_CONFIDENCE_WEIGHT = {GroundingStatus.verified: 20.0, GroundingStatus.unverified: 15.0}

# RuleKey → (subsystem field it reads, default expected value when RuleValue is NULL; None = plain
# truthy check). Before adding a key, check gather_asset_details actually PRODUCES the field: an
# unknown key logs and continues, an absent field is a no-op, so the rule would just never fire.
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
    """One threat's score, rank, whether it made the cut, why, and which rules contributed."""

    threat_id: str
    score: float
    rank: int
    selected: bool
    reason: str
    # `reason` is prose for the reviewer; `rejection` is the same fact for code. Adjacent because
    # they are always assigned together — split them and they drift.
    rejection: ScopingRejection | None = None  # None ⟺ selected; persisted to RejectionKind
    selection: SelectionReason | None = None   # set ⟺ selected; persisted to SelectionKind
    factors: list[dict] = field(default_factory=list)  # every fired rule: {key, family, delta[, gate]}


def _rule_weight(rule: dict, default_weight: float) -> float | None:
    """Metadata `{"weight": N}` override, or None to skip the rule.

    Curator-entered JSON is a trust boundary: log, never crash, never guess. Absent/null → the
    default; a number or numeric string → that weight (0 is legal); a bool or anything unparseable
    → None, because firing with a guessed weight is an effect the curator never chose."""
    meta = rule.get("Metadata")
    if not meta:
        return default_weight
    try:
        weight = json.loads(meta).get("weight")
    except (ValueError, AttributeError):
        log.warning("scoping.rule_metadata_invalid", rule_key=rule.get("RuleKey"))
        return None
    if weight is None:
        return default_weight
    if isinstance(weight, bool):  # bool is not a weight — no-effect, not a guess of 1.0/0.0
        log.warning("scoping.rule_metadata_invalid", rule_key=rule.get("RuleKey"))
        return None
    try:
        return float(weight)
    except (TypeError, ValueError):
        log.warning("scoping.rule_metadata_invalid", rule_key=rule.get("RuleKey"))
        return None


def _matches(value: Any, expected: str | None) -> bool:
    """No expected value → truthy check. Else numeric-tolerant equality ("05"/"5.0"/5 all match),
    falling back to case-insensitive text. Bools never take the float branch: True matches only
    "1"/"true", False only "0"/"false"."""
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


def _apply_rules(threat: dict, subsystems: list[dict] | None, rules_by_type: dict,
                default_rule_weight: float) -> tuple[float, bool, list[str], list[dict]]:
    """Evaluate every rule for this threat's grounded type → (score delta, selected, failed gate
    keys, fired factors).

    The asset is threat-modeled as a whole, so a subsystem-keyed rule fires if ANY supporting
    system matches: a tech_gate passes when any does, a relevance_* weight is added once."""
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
        # an all-None field fail CLOSED. `is not None` keeps a curator's explicit "" or 0
        # evaluated while treating an unresolved field as absent.
        present = [s for s in subs if s.get(fld) is not None]
        if not present:  # unresolved/absent on every supporting system → no-effect rule
            log.warning("scoping.rule_field_absent", rule_key=key, field=fld)
            continue
        # "" is a real curator value (match-empty), NOT "fall back to the default" — only a true
        # NULL RuleValue uses the allowlist entry's default.
        rule_value = rule.get("RuleValue")
        expected = rule_value if rule_value is not None else default_expected
        matched = any(_matches(s.get(fld), expected) for s in present)
        family = rule["RuleType"]
        if family == ThreatRuleType.tech_gate:
            if not matched:
                selected = False
                gate_failures.append(key)
            factors.append({"key": key, "family": str(ThreatRuleType.tech_gate), "delta": 0.0,
                            "gate": "passed" if matched else "failed"})
        elif family in (ThreatRuleType.relevance_flag, ThreatRuleType.relevance_context_value):
            if matched:
                weight = _rule_weight(rule, default_rule_weight)
                if weight is None:  # malformed Metadata → rule skipped (logged in _rule_weight)
                    continue
                delta += weight
                factors.append({"key": key, "family": str(family), "delta": weight})
        else:  # unrecognized family → same no-effect discipline as an unknown key
            log.warning("scoping.rule_type_unknown", rule_type=str(family), rule_key=key)
    return delta, selected, gate_failures, factors


def _scoring_reason(gate_failures: list[str], grounding_status: Any,
                    ) -> tuple[str, ScopingRejection | None, SelectionReason | None]:
    """Prose reason AND the machine-readable kinds, together — never one without the other. The
    SelectionReason is provisional: score_threats clears it if a later cutoff rejects the threat."""
    if gate_failures:
        return f"tech_gate:{','.join(gate_failures)} failed", ScopingRejection.tech_gate, None
    selection = (SelectionReason.verified_match
                if GroundingStatus(grounding_status) == GroundingStatus.verified
                else SelectionReason.unverified_match)
    return f"grounding={grounding_status}", None, selection


def _apply_score_floor(selected: bool, score: float, reason: str,
                    rejection: ScopingRejection | None, *, score_threshold: float | None,
                    ) -> tuple[bool, str, ScopingRejection | None]:
    """The configured score floor, applied in rank order.

    DORMANT under the shipped rulebook, deliberately kept: the lowest reachable score is
    base(50) + unverified(15) = 65 against a threshold of 55. It stays because it is the control a
    curator's negative-weight rule acts through (`_rule_weight` accepts negatives); deleting it
    would make such a rule silently inert.

    No top-N here — tasks._select_unique_top_n owns that cutoff, because duplicates must be folded
    BEFORE slots are counted or a duplicate consumes a slot a distinct threat should have had."""
    if selected and score_threshold is not None and score < score_threshold:
        return False, f"below score threshold ({score_threshold})", ScopingRejection.below_threshold
    return selected, reason, rejection


def score_threats(threats: list[dict[str, Any]], *, subsystems: list[dict] | None = None,
                rules: list[dict] | None = None, score_threshold: float | None = None,
                base_score: float | None = None,
                default_rule_weight: float | None = None) -> list[Scored]:
    """Score and rank the asset's threats and decide which earn a written scenario.

    Deterministic: same inputs → same ranking. `base_score`/`default_rule_weight` fall back to
    config; the pipeline passes the session's resolved tuning so one assessment is never scored
    under two rulebooks. No `top_n` — see _apply_score_floor."""
    if base_score is None or default_rule_weight is None:
        from app.core.config import get_settings  # lazy: keeps import-time coupling minimal
        _s = get_settings()
        base_score = _s.base_score if base_score is None else base_score
        default_rule_weight = (_s.default_rule_weight if default_rule_weight is None
                            else default_rule_weight)
    rules_by_type: dict[int, list[dict]] = {}
    for r in rules or []:
        rules_by_type.setdefault(r["ThreatTypeID"], []).append(r)

    evaluated = []
    for t in threats:
        score = base_score + _CONFIDENCE_WEIGHT.get(GroundingStatus(t["grounding_status"]), 0.0)
        delta, selected, gate_failures, factors = _apply_rules(t, subsystems, rules_by_type,
                                                            default_rule_weight)
        score += delta
        reason, rejection, selection = _scoring_reason(gate_failures, t["grounding_status"])
        evaluated.append((t["threat_id"], score, selected, reason, rejection, selection, factors))

    # Score desc ONLY, relying on list.sort being stable — the incoming order IS the tie-break, and
    # is meaningful on both paths: a fresh run appends in the model's own relevance-ranked proposal
    # order, and regen/next-set comes from dal.active_threats' explicit ORDER BY. Do NOT tie-break
    # on threat_id: dal.guid() puts its random bytes in the LEADING positions, so id order is a
    # lottery — and with scores taking only two distinct values in practice, nearly every threat
    # ties, so that lottery would decide rank and which of two duplicates survives.
    evaluated.sort(key=lambda x: -x[1])
    out: list[Scored] = []
    for rank, (tid, score, selected, reason, rejection, selection, factors) in enumerate(evaluated, start=1):
        selected, reason, rejection = _apply_score_floor(
            selected, score, reason, rejection, score_threshold=score_threshold)
        out.append(Scored(threat_id=tid, score=score, rank=rank, selected=selected, reason=reason,
                        rejection=rejection, selection=selection if selected else None,
                        factors=factors))
    return out
