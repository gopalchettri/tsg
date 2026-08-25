"""Canonical STRIDE order and the coverage QUOTA that selection fills.

WHY THIS MODULE EXISTS. A library threat is genuinely multi-category — 74 of the 75 seeded
Threat_Catalogue rows carry two to four STRIDE memberships, because "Credential phishing and
MFA session theft" really is Spoofing AND Information Disclosure AND Elevation of Privilege at
once. Identified_Threat.ThreatCategory holds exactly one of them, and for a long time that one
was `categories[0]` — the membership list ordered by ThreatCategoryID. The seed numbers those
ids ALPHABETICALLY (Denial of Service = 1 ... Spoofing = 5, Tampering = 6), so the lowest id
won every tie: 46 of 75 library threats were labelled Denial of Service, and Spoofing,
Tampering and Repudiation were labelled on NONE. That is the whole of the "everything is DoS"
symptom, and it was a labelling accident, not a property of the library.

Re-sorting the memberships into canonical STRIDE order and still taking [0] does not fix it —
measured on the same seed it just moves the pile (Spoofing 49). ANY fixed priority applied to
a positional pick has a favourite.

So the category is not picked from the threat at all. It is decided by WHICH SLOT the threat
was selected to fill: allocate() sets the target shape, assign() fills each slot with a
candidate that genuinely carries that category, and the assigned category is what gets stored.
Selection and labelling become one decision, which is what stops the skew coming back — a
distribution that falls out of the algorithm cannot drift the way one maintained by prose in a
prompt can.

Leaf module: stdlib only, so app.db and app.pipeline can both import it (both already import
app.core.*) without an import cycle. Same posture as pipeline/coverage.py, which accounts for
the (subsystem x category) grid these quotas fill.
"""
from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping, Sequence
from typing import Any, TypeVar

T = TypeVar("T")

#: Canonical STRIDE order — the SINGLE definition. prompts.py imports this rather than keeping
#: its own copy, and dal.active_category_names sorts live Threat_Category rows by it, so no
#: consumer ever sees the table's alphabetical id order. Renaming a live category away from
#: these names is caught at boot by db.invariants, not discovered in a threat report.
STRIDE_ORDER: tuple[str, ...] = (
    "Spoofing", "Tampering", "Repudiation",
    "Information Disclosure", "Denial of Service", "Elevation of Privilege",
)

_RANK = {name: i for i, name in enumerate(STRIDE_ORDER)}


def in_stride_order(names: Iterable[str]) -> list[str]:
    """Category names in canonical STRIDE order, de-duplicated.

    A name that is not canonical STRIDE (a renamed or custom Threat_Category) sorts after all
    six and keeps its relative position — the same graceful degradation prompts.py already
    takes for a category with no _STRIDE_SCENARIO_SHAPES line. The sort is stable, so equal
    ranks never reshuffle."""
    seen: list[str] = []
    for n in names:
        if n and n not in seen:
            seen.append(n)
    return sorted(seen, key=lambda n: _RANK.get(n, len(_RANK)))


def allocate(n: int, categories: Iterable[str] | None = None,
             existing: Mapping[str, int] | None = None) -> dict[str, int]:
    """The target shape for n threats: category -> how many slots it gets.

    Round-robin in canonical order, so the count alone decides the spread:
    n=3 -> S,T,R  ·  n=5 -> S,T,R,I,D  ·  n=10 -> S,T,R,I twice each, D,E once.

    `existing` (category -> threats the session ALREADY holds) makes an additive round fill
    what is thin instead of restarting at Spoofing: each slot goes to whichever category has
    the lowest running total, canonical order breaking ties. Without it a second "generate next
    set" click would re-target the same categories the first one already filled."""
    cats = in_stride_order(categories) if categories is not None else list(STRIDE_ORDER)
    if n <= 0 or not cats:
        return {}
    rank = {c: i for i, c in enumerate(cats)}
    have = dict(existing or {})
    quota = dict.fromkeys(cats, 0)
    for _ in range(n):
        pick = min(cats, key=lambda c: (have.get(c, 0) + quota[c], rank[c]))
        quota[pick] += 1
    return {c: k for c, k in quota.items() if k > 0}


def assign(candidates: Sequence[T], quota: Mapping[str, int],
           categories_of: Callable[[T], Iterable[str]]) -> list[tuple[T, str]]:
    """Fill each quota slot with a candidate that genuinely carries that category.

    Returns (candidate, assigned_category) pairs; the assigned category is what the caller
    stores as the threat's ThreatCategory. `candidates` must arrive best-first (retrieval
    score) — that ordering is preserved WITHIN each category, so ranking still decides which
    Spoofing threat wins the Spoofing slot; it just no longer decides how many Spoofing slots
    there are.

    Slots are walked round by round rather than category by category, so a category holding two
    slots does not take its second before every other category has had its first.

    SOFT, by design: a category no candidate can serve does not hold its slot empty and does not
    shrink the result — the slot is reallocated to a candidate that is left. The unanswered cell
    is still reported by pipeline.coverage.coverage_report, which is the right place for it;
    fabricating a threat to fill it is the failure this must never trade for.
    """
    remaining = {c: int(k) for c, k in quota.items() if k > 0}
    total = sum(remaining.values())
    used: set[int] = set()
    out: list[tuple[T, str]] = []
    if total <= 0:
        return out
    memo: dict[int, list[str]] = {}

    def cats_at(i: int) -> list[str]:
        if i not in memo:
            memo[i] = in_stride_order(categories_of(candidates[i]))
        return memo[i]

    def first_eligible(cat: str) -> int | None:
        return next((i for i in range(len(candidates))
                     if i not in used and cat in cats_at(i)), None)

    while len(out) < total:
        progressed = False
        for cat in in_stride_order(remaining):
            if remaining.get(cat, 0) <= 0:
                continue
            i = first_eligible(cat)
            if i is None:
                continue          # nothing carries it — the pass below reallocates the slot
            used.add(i)
            remaining[cat] -= 1
            out.append((candidates[i], cat))
            progressed = True
            if len(out) >= total:
                break
        if not progressed:
            break

    for i in range(len(candidates)):
        if len(out) >= total:
            break
        if i in used:
            continue
        cats = cats_at(i)
        if not cats:
            continue              # grid-unplaceable, same rule as coverage.covered_cells
        used.add(i)
        out.append((candidates[i], cats[0]))
    return out


def achieved(assigned: Iterable[tuple[Any, str]]) -> dict[str, int]:
    """category -> how many slots assignment actually filled.

    Two jobs. It is `existing` for the follow-up allocate() that tells gap generation which
    categories the library could not supply — allocate(shortfall, cats, existing=achieved(...))
    is why there is no separate "residual" helper: re-allocating the remaining slots against
    what is already held lands on the same answer AND stays correct when the shortfall grew
    because dedup dropped a row after assignment. It is also what goes into the
    grounding_summary audit row, so a future skew shows up in recorded data instead of only in
    a reviewer's impression of a report."""
    out: dict[str, int] = {}
    for _, cat in assigned:
        out[cat] = out.get(cat, 0) + 1
    return out
