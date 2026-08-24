"""Coverage accounting — the safety gate of the library-first redesign.

The threat space is a MATRIX TO FILL, not a list to search: every (subsystem x STRIDE
category) cell must end a session holding either a threat or a recorded, reviewable
justification for non-applicability. An empty cell is a reportable gap, never a silent
omission — a threat model missing the one threat that matters looks identical to a complete
one, so incompleteness must be made structurally visible rather than hoped away.

Leaf module: stdlib only, so any pipeline stage can call it without an import cycle.
Cells are keyed (subsystem_id, category_name); subsystem_id 0 is the asset itself
(tasks.ASSET_UNIT_ID) and every other row is one supporting system. find_threats records a
threat against the asset AND each system a tech_gate does not rule out
(threat_retrieval.attribute_to_subsystems), so the grid is genuinely 2D: a 3-system asset
answers 4 x 6 = 24 questions, not 6.
"""
from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any

Cell = tuple[int, str]


def required_cells(subsystem_ids: Iterable[int], categories: Iterable[str]) -> set[Cell]:
    """Every (subsystem, category) question the session must answer. Category names are
    taken as given (the caller passes active Threat_Category names) — no normalisation,
    because the same caller supplies both sides of the comparison."""
    subs = list(subsystem_ids)
    return {(s, c) for s in subs for c in categories}


def covered_cells(threats: Iterable[Mapping[str, Any]]) -> set[Cell]:
    """Cells answered by a threat. Each threat contributes one cell per category it carries:
    `categories` (list — the Threat_Catalogue_Category_Map memberships, MULTI-category by
    design) when present, else the single `category` string. A threat with no category
    answers nothing — it cannot be placed on the grid."""
    out: set[Cell] = set()
    for t in threats:
        sub = t.get("subsystem_id")
        if sub is None:
            continue
        cats = t.get("categories") or ([t["category"]] if t.get("category") else [])
        out.update((int(sub), c) for c in cats if c)
    return out


def coverage_gaps(subsystem_ids: Iterable[int], categories: Iterable[str],
                  threats: Iterable[Mapping[str, Any]],
                  justified_na: Iterable[Cell] = ()) -> list[Cell]:
    """The still-unanswered cells, deterministically ordered. A cell is answered by a threat
    OR by a justified not-applicable record — never by silence."""
    return sorted(required_cells(subsystem_ids, categories)
                  - covered_cells(threats) - set(justified_na))


def coverage_report(subsystem_ids: Iterable[int], categories: Iterable[str],
                    threats: Iterable[Mapping[str, Any]],
                    justified_na: Iterable[Cell] = ()) -> dict[str, Any]:
    """The session-level coverage verdict: cell counts plus the named gaps. `unexplained`
    must be 0 for a clean session — anything else is surfaced, never absorbed."""
    required = required_cells(subsystem_ids, categories)
    covered = covered_cells(threats) & required
    na = set(justified_na) & required
    gaps = sorted(required - covered - na)
    return {
        "cells": len(required),
        "covered": len(covered),
        "justified_na": len(na),
        "unexplained": len(gaps),
        "gaps": gaps,
    }
