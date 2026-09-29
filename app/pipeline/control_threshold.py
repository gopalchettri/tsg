"""Control-relevance CUTOFF maths: a measured score distribution in, a recommended threshold out.

Pure, like ``control_relevance``: no ``Session``, no ``LLMClient``, no network, no settings lookup,
no printing. Every function here is a function of its arguments alone, so it unit-tests with no
fixtures — which matters because the measurement that FEEDS it cannot be tested at all (it needs a
live library, a live embedder and a live reranker).

WHY IT LIVES IN ``app/`` AND NOT IN THE SCRIPT THAT BORN IT. This maths used to exist only inside
``scripts/measure_control_map_scores.py``. It is now called from two places — that script, and the
application — and two copies of a decision rule is the defect class this codebase keeps paying for
(see ``control_relevance``: two control-query builders drifted, so the same library answered one
pass and not the other). One home, both callers import it.

WHAT A CALLER MAY DO WITH THE ANSWER — a design constraint, not a footnote.
``recommend_relevance_cutoff`` returns TWO numbers and they are not interchangeable:

* ``safe`` is the one to store or act on. It is safe BY CONSTRUCTION against the silent failure
  this whole measurement exists to price: no scenario loses all of its CLEARING matches at it.
* ``stricter_alternative`` is to be RECORDED and shown, never selected automatically. It is the
  strictest cutoff the measured distribution still supports while STRANDING no more than
  ``STRICTER_ALTERNATIVE_STRANDED_FRACTION`` of the measured scenarios — see
  ``stricter_cutoff_alternative`` for the bound, which is a COUNT of scenarios and is wider than 5%
  on a small sample. A stranded scenario keeps no match that clears the cutoff, so production falls
  back to backfilling it with nearest matches capped at ``control_map_min_count``, and it publishes
  ``controls: []`` only when even its best match sits below ``control_map_backfill_ratio`` x the
  cutoff. That last case is the expensive one: the API documents an empty ``controls`` list as a
  healthy library gap, so the cost is invisible in the response and lands on a human reviewer who
  concludes the library does not cover their asset. Trading scenarios away for tidiness is the
  OPERATOR'S call; a route that quietly picks it has made that call on their behalf and hidden it.

``safe`` can be ``None``, and that is an answer too: it means the shortlists were empty, the fault
is in retrieval, and no threshold fixes it. A caller must surface that state rather than coercing
it to a number.

``stricter_alternative`` can be ``None`` INDEPENDENTLY of ``safe``, and means something else
entirely: the measurement found no cutoff above ``safe`` that it could offer inside the stranding
budget, so there is no alternative to record — not "the alternative is zero" and not "the
alternative is ``safe``". A CALLER MUST NOT ``float()`` IT WITHOUT A NONE GUARD; the two numbers are
nullable for different reasons and a caller that guards only ``safe`` will raise on the other.

WHY THE STRICTER ALTERNATIVE IS NOW READ OFF THE SAME DISTRIBUTION AS ``safe``. It used to be the
5th percentile of the best-match scores, computed with no reference to the sweep, to ``safe``, or to
how many scenarios it actually stranded — so "stricter" held only by coincidence of sample size. On
a handful of scenarios (which is what a fresh environment measures) the percentile's rank floored to
the MINIMUM best match, which is by definition at or above ``safe``: the recorded alternative came
back as the same number as the stored cutoff, stranding nobody, while the operator report printed it
as a trade that "accepts ~5% of scenarios going empty". The ledger keeps it in
``Grounding_Calibration_Run.LowestPositive`` and the status route hands it straight back, so a row
that recorded a real trade and a row that recorded nothing were indistinguishable — and a reader
comparing the two columns would conclude the cutoff was already as strict as the evidence allowed.
Both numbers now come off one measured curve, and the strict inequality is CHECKED rather than
assumed (``stricter_cutoff_alternative``).
"""
from __future__ import annotations

import math
import statistics
from collections.abc import Sequence
from typing import Any, NamedTuple

#: Thresholds the report walks. Wide on purpose — the point is to SEE where the cliff is, and a
#: narrow sweep around today's value would hide a cliff sitting just outside it.
DEFAULT_THRESHOLD_SWEEP = (0, 10, 20, 30, 40, 50, 55, 60, 65, 70, 75, 80, 85, 90, 95)

#: One scenario's reranked shortlist: (row, score) pairs, best first. The row payload is never read
#: here — only the scores decide a cutoff — so it is typed as `Any` rather than restated.
ScoredMatches = Sequence[tuple[Any, float]]

#: (threshold, scenarios with NO match clearing it, mean clearing matches per scenario).
#: The middle field is NOT "scenarios that publish an empty list" — production backfills beneath the
#: cutoff. See `sweep_relevance_thresholds`, which is the one place that difference is explained.
ThresholdOutcome = tuple[int, int, float]

#: The share of measured scenarios `stricter_cutoff_alternative` may strand. 5% because that is the
#: number every surface already quotes for this field (the operator script's report line, the admin
#: status route's schema, `record_control_map_finished`); it is a ceiling on a COUNT of scenarios
#: rather than a promise about the fraction — on fewer than 20 scenarios one scenario is already
#: more than 5%, and `stricter_cutoff_alternative` documents what happens there.
STRICTER_ALTERNATIVE_STRANDED_FRACTION = 0.05


def percentile_nearest_rank(values: Sequence[float], percentile: float) -> float:
    """Nearest-rank percentile: the smallest observed value at or below which at least `percentile`%
    of the sample sits, i.e. ``ordered[ceil(percentile/100 * n) - 1]`` with the rank clamped into
    ``[1, n]``. That is the textbook/NIST nearest-rank definition, and it is the one this function's
    NAME has always claimed.

    IT DID NOT USED TO IMPLEMENT IT. The index was ``round(percentile/100 * (n - 1))`` — the rounded
    LINEAR-INTERPOLATION position (numpy's ``method='nearest'``), a different definition that also
    inherited Python's banker's rounding on the .5 boundary: ``p50`` of ``[1, 2, 3, 4]`` came back as
    3.0, where nearest-rank gives 2.0 and ``statistics.median`` gives 2.5. The operator report prints
    one of these as "median", so the name mattered: a future reader correcting the code to match the
    name would have moved a number the report presents as measured, with no test failing.

    NOT ``statistics.quantiles``: that interpolates (so it can return a value nobody observed) and
    raises below n = 2, and this runs on samples as small as a handful of scenarios in a fresh
    environment. An empty sample returns NaN rather than raising, because both callers print a
    distribution table and a missing column must not take the report down; NaN is safe HERE only
    because no caller stores this value — see the class note on `RelevanceCutoffRecommendation` for
    why the cutoff maths returns None instead.

    REPORT-ONLY as of the stricter-alternative fix. No stored number is derived from this function
    any more: `stricter_cutoff_alternative` reads the order statistic it needs straight off the
    measured scores, because it needs to know how many scenarios a candidate cutoff strands and a
    percentile cannot say."""
    if not values:
        return float("nan")
    ordered = sorted(values)
    rank = math.ceil(percentile / 100.0 * len(ordered))      # 1-based; <= 0 for percentile <= 0
    return ordered[min(len(ordered), max(1, rank)) - 1]


def sweep_relevance_thresholds(results: Sequence[ScoredMatches], top_k: int,
                            thresholds: tuple[int, ...] = DEFAULT_THRESHOLD_SWEEP,
                            ) -> list[ThresholdOutcome]:
    """(threshold, scenarios with NO match clearing it, mean clearing matches per scenario).

    Capped at top_k because production caps there (`control_map_max_count`) — counting uncapped
    matches would overstate what a threshold actually delivers.

    THE MIDDLE COLUMN IS NOT "SCENARIOS THAT PUBLISH ``controls: []``", and this docstring used to
    say it was. Production's selection rule has a third step after the cutoff and the ceiling: when
    fewer than ``control_map_min_count`` matches clear the cutoff, the best remaining matches
    BACKFILL up to that floor, admitted down to ``control_map_backfill_ratio`` x the cutoff in force
    (``control_relevance.select_applicable_controls``, floor resolved by
    ``control_mapping._backfill_floor``). A scenario counted here therefore still publishes
    controls — nearest matches, booked separately as ``backfilled_count`` and capped at
    ``min_count`` instead of ``max_count`` — and publishes an empty list only when even its best
    match falls below that floor. This column is an UPPER BOUND on the silent-empty risk, not the
    risk itself, and the wording mattered because comments in this codebase are what the next reader
    cites when deciding a cutoff is safe.

    THE BACKFILL IS DELIBERATELY NOT MODELLED, and that is a decision with a number behind it, not
    an omission. Model it and this column becomes "no match reached ``ratio`` x t", which at the
    default ratio and the STRICTEST swept value is 0.42 x 95 = 39.9 — so every scenario whose best
    control scores 40 or better is empty at NO swept threshold, which on any real reranked
    distribution means `recommend_relevance_cutoff` returns the top of the sweep. That
    recommendation is not merely optimistic, it is self-defeating: at the top of the sweep almost
    nothing clears the cutoff, so nearly every scenario is served by the backfill path — capped at
    ``control_map_min_count`` (5) rather than ``control_map_max_count`` (25) — and the measurement
    would have recommended a cutoff that shrinks every scenario's control list to the emergency floor
    and makes every published control a nearest match admitted by shortfall rather than by relevance.
    The backfill is a floor under the damage of a cutoff set too high; spending it to justify setting
    the cutoff higher buys nothing and costs the mean. The cutoff's own job — telling a real match
    from a nearest one — is exactly what the pre-backfill curve measures, so that is the curve the
    recommendation is read off. Pinned by
    ``test_modelling_the_backfill_would_recommend_the_top_of_the_sweep``.

    An operator who wants the post-backfill count can derive it from the same shortlists without a
    second sweep: a scenario publishes nothing at cutoff t only when its BEST match is below
    ``control_map_backfill_ratio`` x t."""
    rows = []
    for t in thresholds:
        kept = [min(top_k, sum(1 for _row, score in matches if score >= t))
                for matches in results]
        rows.append((t, sum(1 for k in kept if k == 0),
                    statistics.mean(kept) if kept else 0.0))
    return rows


class RelevanceCutoffRecommendation(NamedTuple):
    """The two numbers, named so a caller cannot swap them by accident.

    A bare 2-tuple let `safe, stricter = recommend(...)` be written either way round, and the two
    are numerically similar enough that the mix-up would read as plausible — while meaning
    "quietly accept scenarios publishing no controls". See the module docstring: `safe` is
    stored, `stricter_alternative` is recorded and offered.

    BOTH ARE NULLABLE AND THEY DO NOT MEAN THE SAME THING BY IT. `safe is None` means retrieval
    faulted — even a cutoff of 0 leaves scenarios with nothing, so the shortlists were empty.
    `stricter_alternative is None` means there was no stricter cutoff to offer, which is the normal
    answer on a small sample and says nothing at all about retrieval. Neither may be coerced: a 0
    would admit every control at every score while claiming to have been measured, and this field
    used to degrade to NaN, which is worse than None in both directions — it survives `float()`,
    reaches `Grounding_Calibration_Run.LowestPositive` (a column that cannot hold it) and prints as
    "nan" in a report."""
    safe: int | None
    stricter_alternative: float | None


def stricter_cutoff_alternative(safe: int | None,
                            best_match_scores: Sequence[float]) -> float | None:
    """The strictest cutoff the measured scores support while stranding a BOUNDED, counted share of
    the scenarios — or None when the measurement has no such cutoff to offer.

    WHAT "STRANDED" MEANS HERE: no match clearing the cutoff, which is the same quantity
    `sweep_relevance_thresholds` counts (read that docstring — it is NOT the same as publishing
    ``controls: []``, because production backfills beneath the cutoff).

    THE MATHS, which is one line of arithmetic and one line of proof. A cutoff t strands exactly the
    scenarios whose best match is below t, so with the best matches sorted ascending as
    ``b[0] <= b[1] <= ... <= b[n-1]``, ``b[k]`` strands ``#{i : b[i] < b[k]} <= k`` of them — at most
    k by sortedness alone, fewer when scores tie — and every cutoff above ``b[k]`` strands at least
    k + 1. So ``b[budget]`` IS the strictest cutoff inside a budget of `budget` stranded scenarios,
    exactly, with no percentile convention to argue about.

    THE BUDGET is ``STRICTER_ALTERNATIVE_STRANDED_FRACTION`` of the sample, FLOORED AT ONE SCENARIO
    and required to stay below the whole sample:

        * n >= 20 — 5% of the scenarios, rounded down: the documented trade, measured.
        * 2 <= n < 20 — one scenario, which is 1/n and therefore MORE than 5%. Offered anyway,
          because the alternative below 20 scenarios is to offer nothing at all, and a real cutoff
          with a real cost of one named scenario is worth more to an operator than silence. Whoever
          prints it must print the count, not the nominal 5%.
        * n < 2 — None. One scenario has no tail to price: every stricter cutoff strands 100% of the
          sample, and a "5% alternative" computed over a single observation is the exact kind of
          number that reads as measured and is not.

    THE STRICT INEQUALITY IS CHECKED, NOT ASSUMED, and that check is the whole point of this
    function existing. `safe` is a SWEPT value and is therefore at or below ``b[0]`` (it is the
    highest swept threshold stranding nobody), so ``b[budget]`` is normally well above it — but not
    when the bottom of the distribution is a flat tie that lands exactly on a swept step, and the
    old percentile-based version returned that tie as an "alternative" identical to the stored
    cutoff. Equal is not stricter: it returns None instead, because a number that reads as a
    measured trade and costs nothing is worse than the absence of one."""
    if safe is None:
        return None                      # retrieval faulted; there is nothing to be stricter than
    ordered = sorted(best_match_scores)
    budget = max(1, int(len(ordered) * STRICTER_ALTERNATIVE_STRANDED_FRACTION))
    if budget >= len(ordered):
        return None                      # fewer than two measured scenarios: no tail to trade
    alternative = float(ordered[budget])
    return alternative if alternative > safe else None


def recommend_relevance_cutoff(rows: Sequence[ThresholdOutcome],
                            best_match_scores: Sequence[float]) -> RelevanceCutoffRecommendation:
    """(safe threshold, stricter alternative).

    Safe = the HIGHEST swept value at which no scenario loses all its clearing matches. None when
    even 0 leaves scenarios stranded, which means their shortlists were empty and the fault is in
    retrieval, not the cutoff — a threshold recommendation there would be noise dressed as an
    answer. The stricter alternative trades a counted handful of scenarios for a cleaner tail; it is
    offered, never chosen here, because that trade is the operator's to make.

    THE TWO ARGUMENTS MUST DESCRIBE THE SAME POPULATION: `rows` from `sweep_relevance_thresholds`
    over the measured shortlists, `best_match_scores` the best match of each of those same
    scenarios. They are not cross-checked, because there is nothing in `rows` to check against — a
    ThresholdOutcome carries counts, not the sample — but `stricter_cutoff_alternative`'s strict
    ``> safe`` test degrades to None rather than to a wrong number when they disagree, which is what
    the previous version did not: it took a percentile of one population and printed it against a
    cutoff measured over another."""
    safe = max((t for t, empty, _mean in rows if empty == 0), default=None)
    return RelevanceCutoffRecommendation(safe, stricter_cutoff_alternative(safe, best_match_scores))
