"""Threat scoping — deterministic scoring and selection.

Score = base score + grounding-confidence weight, ranked descending, with an optional score
floor. The old `Config_Threat_Rule` engine (tech_gates and relevance weights) was REMOVED
2026-08: rule evaluation read only supporting systems and never the asset's own declared type,
so on mixed assets the gates silently deleted correct threats (all 17 OT-gated types off an OT
asset whose supporting systems were IT). Asset-level relevance is the Stage-1a LLM validator's
job (tasks._validate_candidates) — its failure mode is visible extra candidates, never an
invisible omission, which is the property a GRC assessment cannot trade away.

Same inputs → same ranking.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from app.core.enums import (
    GroundingStatus,
    ScopingRejection,
    SelectionReason,
)
from app.core.logging import get_logger

log = get_logger(__name__)

# base_score arrives as a score_threats parameter, never a module literal, so a Config_Tuning
# session snapshot can override it per assessment.
#
# unverified (novel) threats must land ABOVE scoping_score_threshold (default 55) or a curator
# never sees what they haven't catalogued: 15.0 puts them at 65, below a real library match
# (verified 70) but comfortably surfaced. Grounding confidence ALONE must never reject a threat.
_CONFIDENCE_WEIGHT = {GroundingStatus.verified: 20.0, GroundingStatus.unverified: 15.0}


@dataclass
class Scored:
    """One threat's score, rank, whether it made the cut, and why."""

    threat_id: str
    score: float
    rank: int
    selected: bool
    reason: str
    # `reason` is prose for the reviewer; `rejection` is the same fact for code. Adjacent because
    # they are always assigned together — split them and they drift.
    rejection: ScopingRejection | None = None  # None ⟺ selected; persisted to RejectionKind
    selection: SelectionReason | None = None   # set ⟺ selected; persisted to SelectionKind
    # Always [] since the rule engine's removal; the field (and Scoped_Threat.FactorsJSON it
    # persists to) stays so the column contract, the variant-cloning read and historical rows
    # keep working unchanged. ScopingRejection.tech_gate likewise remains readable on old rows.
    factors: list[dict] = field(default_factory=list)


def _scoring_reason(grounding_status: Any,
                    ) -> tuple[str, ScopingRejection | None, SelectionReason | None]:
    """Prose reason AND the machine-readable kinds, together — never one without the other. The
    SelectionReason is provisional: score_threats clears it if a later cutoff rejects the threat."""
    selection = (SelectionReason.verified_match
                if GroundingStatus(grounding_status) == GroundingStatus.verified
                else SelectionReason.unverified_match)
    return f"grounding={grounding_status}", None, selection


def _apply_score_floor(selected: bool, score: float, reason: str,
                    rejection: ScopingRejection | None, *, score_threshold: float | None,
                    ) -> tuple[bool, str, ScopingRejection | None]:
    """The configured score floor, applied in rank order.

    DORMANT under the shipped defaults, deliberately kept: the lowest reachable score is
    base(50) + unverified(15) = 65 against a threshold of 55. It stays because
    `scoping_score_threshold` is a real Config_Tuning knob — an operator raising it above 65 is
    choosing to require verified grounding, and deleting the floor would make that knob
    silently inert.

    No top-N here — tasks._select_unique_top_n owns that cutoff, because duplicates must be folded
    BEFORE slots are counted or a duplicate consumes a slot a distinct threat should have had."""
    if selected and score_threshold is not None and score < score_threshold:
        return False, f"below score threshold ({score_threshold})", ScopingRejection.below_threshold
    return selected, reason, rejection


def score_threats(threats: list[dict[str, Any]], *, score_threshold: float | None = None,
                base_score: float | None = None) -> list[Scored]:
    """Score and rank the asset's threats and decide which earn a written scenario.

    Deterministic: same inputs → same ranking. `base_score` falls back to config; the pipeline
    passes the session's resolved tuning so one assessment is never scored under two rulebooks."""
    if base_score is None:
        from app.core.config import (
            get_settings,  # lazy: keeps import-time coupling minimal
        )
        base_score = get_settings().base_score

    evaluated = []
    for t in threats:
        score = base_score + _CONFIDENCE_WEIGHT.get(GroundingStatus(t["grounding_status"]), 0.0)
        reason, rejection, selection = _scoring_reason(t["grounding_status"])
        evaluated.append((t["threat_id"], score, True, reason, rejection, selection))

    # Score desc ONLY, relying on list.sort being stable — the incoming order IS the tie-break, and
    # is meaningful on both paths: a fresh run appends in the model's own relevance-ranked proposal
    # order, and regen/next-set comes from dal.active_threats' explicit ORDER BY. Do NOT tie-break
    # on threat_id: dal.guid() puts its random bytes in the LEADING positions, so id order is a
    # lottery — and with scores taking only two distinct values in practice, nearly every threat
    # ties, so that lottery would decide rank and which of two duplicates survives.
    evaluated.sort(key=lambda x: -x[1])
    out: list[Scored] = []
    for rank, (tid, score, selected, reason, rejection, selection) in enumerate(evaluated, start=1):
        selected, reason, rejection = _apply_score_floor(
            selected, score, reason, rejection, score_threshold=score_threshold)
        out.append(Scored(threat_id=tid, score=score, rank=rank, selected=selected, reason=reason,
                        rejection=rejection, selection=selection if selected else None,
                        factors=[]))
    return out
