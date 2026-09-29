"""Pins the decision math in app/pipeline/control_threshold.py.

The measurement that feeds it (scripts/measure_control_map_scores.py) needs a live database and
real models, so it cannot run in CI — but the part an operator ACTS on is pure: given per-scenario
match scores, which threshold does it recommend? A wrong answer there is set into
TSG_CONTROL_MAP_MIN_SCORE by hand, or stored by the admin route that now runs the same measurement,
and then silently empties every scenario's control list, which the API reports as a healthy library
gap. So the math is tested here even though the I/O around it cannot be.

It is imported normally now. It used to be loaded out of scripts/ with importlib because that was
its only home; moving it into app/pipeline means the script and the application share ONE copy —
and that this test covers the copy the application runs, not a look-alike.

THE PINS BELOW ARE MOSTLY PROPERTY-STYLE (a range of sample sizes, one invariant) rather than one
hand-built example each, because every defect this file has caught so far was a formula that held on
the one sample somebody happened to write down and broke on the sample sizes a real environment
measures. `stricter_alternative` equalling the stored cutoff on a 3-scenario sample got past two
example-based assertions in exactly that way.
"""
import math
import statistics

from app.pipeline.control_threshold import (
    DEFAULT_THRESHOLD_SWEEP,
    STRICTER_ALTERNATIVE_STRANDED_FRACTION,
    percentile_nearest_rank,
    recommend_relevance_cutoff,
    stricter_cutoff_alternative,
    sweep_relevance_thresholds,
)


def _matches(*scores):
    """One scenario's reranked shortlist; the row payload is irrelevant to the math."""
    return [({}, s) for s in scores]


def _population(n, low=55.0, high=95.0, depth=10):
    """`n` scenarios whose BEST matches are evenly spread over [low, high], each with a `depth`-deep
    shortlist decaying below it — the shape a real reranked shortlist has, which matters for the
    mean-controls column. Evenly spread rather than random: the invariants below must hold for EVERY
    sample size, and a seeded random population would pin one draw per size while reading as a
    sweep."""
    step = (high - low) / max(1, n - 1)
    bests = [low + i * step for i in range(n)]
    return [_matches(*[max(0.0, b - 2.0 * rank) for rank in range(depth)]) for b in bests], bests


def _stranded(best_match_scores, cutoff):
    """Scenarios with NO match clearing `cutoff` — the quantity the sweep's middle column counts."""
    return sum(1 for score in best_match_scores if score < cutoff)


def test_sweep_counts_unclear_scenarios_and_caps_at_top_k():
    results = [_matches(95.0, 80.0, 40.0), _matches(50.0, 45.0)]
    rows = {t: (empty, mean) for t, empty, mean in sweep_relevance_thresholds(
        results, top_k=2, thresholds=(0, 60, 90))}
    # at 0 both scenarios keep matches, but CAPPED at top_k=2 — not 3 and 2
    assert rows[0] == (0, 2.0)
    # at 60 only the first scenario has anything left
    assert rows[60] == (1, 1.0)
    # at 90 one match survives in total, so one scenario is stranded and the mean is 0.5
    assert rows[90] == (1, 0.5)


def test_recommend_picks_the_highest_threshold_that_strands_nobody():
    results = [_matches(95.0, 80.0), _matches(70.0, 65.0), _matches(62.0)]
    rows = sweep_relevance_thresholds(results, top_k=5, thresholds=(0, 50, 60, 65, 70))
    safe, _stricter = recommend_relevance_cutoff(rows, [95.0, 70.0, 62.0])
    # 60 keeps every scenario; 65 would strand the third (its best match is 62)
    assert safe == 60


def test_recommend_refuses_when_even_zero_leaves_scenarios_empty():
    """An empty shortlist is a RETRIEVAL fault — the embedding group is unpopulated, say. No
    threshold fixes it, so the script must not hand back a number that looks like a fix."""
    results = [_matches(90.0), []]
    rows = sweep_relevance_thresholds(results, top_k=5, thresholds=(0, 50))
    safe, _stricter = recommend_relevance_cutoff(rows, [90.0])
    assert safe is None


def test_recommend_refuses_when_every_measured_scenario_came_back_empty():
    """The whole-population version of the refusal above: not one scenario shortlisted anything, so
    there are no best-match scores either. Both halves of the answer must degrade — and BOTH to
    None. The stricter alternative used to degrade to NaN here, which is worse than None in both
    directions: NaN survives `float()`, so it reaches Grounding_Calibration_Run.LowestPositive (a
    SQL FLOAT column that cannot hold it) and prints as "nan" in the operator report, whereas None
    is the state every consumer of this field already models."""
    rows = sweep_relevance_thresholds([[], [], []], top_k=5, thresholds=(0, 50, 90))
    assert [empty for _t, empty, _mean in rows] == [3, 3, 3]
    safe, stricter = recommend_relevance_cutoff(rows, [])
    assert safe is None
    assert stricter is None


# ---------------------------------------------------------------------------
# The stricter alternative
# ---------------------------------------------------------------------------

def test_the_stricter_alternative_is_offered_never_chosen():
    """`safe` and `stricter_alternative` are different numbers with different risks, and the
    stricter one is always the HIGHER of the two — that is the whole point of it. Whatever consumes
    this (the script's report, the admin route that stores the result) must act on `safe`; nothing
    here may quietly promote the stricter value into it."""
    # One outlier scenario whose best match is 55 holds `safe` down to 50, while 95% of scenarios
    # score far above it — so the alternative lands well above the safe cutoff and costs exactly the
    # one scenario that 5% of 20 buys.
    results = [_matches(55.0)] + [_matches(92.0, 88.0)] * 19
    rows = sweep_relevance_thresholds(results, top_k=5, thresholds=(0, 50, 60, 90))
    best = [55.0] + [92.0] * 19
    recommendation = recommend_relevance_cutoff(rows, best)
    assert recommendation.safe == 50                 # 60 would strand the outlier scenario
    assert recommendation.stricter_alternative == 92.0
    assert _stranded(best, recommendation.stricter_alternative) == 1   # 5% of 20, as documented
    # Field names, not positions: the two are numerically plausible either way round, so a caller
    # that swapped them would read as correct. See the module docstring.
    assert tuple(recommendation) == (50, 92.0)


def test_a_handful_of_scenarios_no_longer_offers_the_stored_cutoff_as_its_own_alternative():
    """THE REGRESSION. `stricter_alternative` used to be a percentile of the best-match scores taken
    with no reference to the sweep or to `safe`, and on a small sample its rank floored to the
    MINIMUM best match — which is by definition at or above `safe`. Three scenarios scoring
    60/70/80 produced safe=60 and "stricter alternative"=60.0: the same number, stranding nobody,
    printed by the operator report as a trade that "accepts ~5% of scenarios going empty" and stored
    in the ledger column an operator compares against the cutoff. A row that recorded a real trade
    and a row that recorded nothing were indistinguishable."""
    best = [60.0, 70.0, 80.0]
    rows = sweep_relevance_thresholds([_matches(b) for b in best], top_k=5)
    recommendation = recommend_relevance_cutoff(rows, best)
    assert recommendation.safe == 60
    assert recommendation.stricter_alternative == 70.0, (
        "the strictest cutoff that strands at most one of three scenarios is the second-lowest best "
        "match, not the lowest")
    assert recommendation.stricter_alternative != recommendation.safe
    assert _stranded(best, recommendation.stricter_alternative) == 1


def test_the_stricter_alternative_is_strictly_stricter_and_costs_a_bounded_count():
    """The two properties that make the field worth recording at all, over every sample size a real
    environment can measure. Either it is None, or it is strictly above `safe` AND strands at least
    one and at most `max(1, 5% of n)` scenarios. Anything else is noise with a reassuring name."""
    for n in range(1, 61):
        results, best = _population(n)
        recommendation = recommend_relevance_cutoff(
            sweep_relevance_thresholds(results, top_k=5), best)
        assert recommendation.safe is not None, n    # every best match here clears 0
        alternative = recommendation.stricter_alternative
        if n < 2:
            assert alternative is None, "one scenario has no tail to price"
            continue
        budget = max(1, math.floor(n * STRICTER_ALTERNATIVE_STRANDED_FRACTION))
        assert alternative is not None and alternative > recommendation.safe, (n, recommendation)
        assert 1 <= _stranded(best, alternative) <= budget, (n, alternative)


def test_the_stranding_cost_is_within_five_percent_once_twenty_scenarios_are_measured():
    """The bound the report, the API schema and record_control_map_finished all quote. It is a
    promise about the COUNT, so it only becomes a promise about 5% once the sample can express 5% —
    below 20 scenarios one scenario is more than 5% and that is stated rather than rounded away."""
    for n in range(20, 121):
        _results, best = _population(n)
        alternative = stricter_cutoff_alternative(50, best)
        assert alternative is not None, n
        assert _stranded(best, alternative) / n <= STRICTER_ALTERNATIVE_STRANDED_FRACTION, n
    for n in range(2, 20):
        _results, best = _population(n)
        assert _stranded(best, stricter_cutoff_alternative(50, best)) == 1, (
            f"below 20 scenarios the budget floors at ONE scenario, which is {1 / n:.0%} of n — "
            "whoever prints this must print the count, never the nominal 5%")


def test_a_flat_bottom_of_the_distribution_offers_no_alternative_rather_than_an_equal_one():
    """The case the old percentile got wrong and the only way the current formula can come back
    empty-handed with a real `safe`: enough scenarios tie at the bottom that the strictest in-budget
    cutoff IS that tie, and the tie lands exactly on a swept step. Equal is not stricter, so there
    is nothing to offer — None, never `safe` wearing a different name."""
    best = [60.0] * 4 + [90.0] * 6
    rows = sweep_relevance_thresholds([_matches(b) for b in best], top_k=5)
    recommendation = recommend_relevance_cutoff(rows, best)
    assert recommendation.safe == 60
    assert recommendation.stricter_alternative is None


def test_a_mismatched_sweep_and_score_sample_degrade_to_no_alternative():
    """`rows` and `best_match_scores` must describe the same population and nothing in a
    ThresholdOutcome can prove they do — a sweep over ZERO results reports nobody stranded at every
    threshold, so `safe` comes back as the top of the sweep from no evidence whatsoever (which is
    why both callers refuse before they get here, see grounding.measure_control_map_cutoff). The
    strict `> safe` test is what keeps that from also producing a plausible-looking alternative."""
    _results, best = _population(50)
    safe, stricter = recommend_relevance_cutoff(sweep_relevance_thresholds([], top_k=5), best)
    assert safe == max(DEFAULT_THRESHOLD_SWEEP)
    assert stricter is None


# ---------------------------------------------------------------------------
# What the sweep's middle column does and does not model
# ---------------------------------------------------------------------------

def test_a_scenario_in_the_backfill_band_is_counted_stranded_but_publishes_controls():
    """The sweep's middle column is an UPPER BOUND on scenarios publishing `controls: []`, not the
    count of them, and the docstring that claimed otherwise is what a future reader would have cited
    when deciding a cutoff was safe. Cross-checked against the REAL floor resolver so the claim
    cannot drift: at cutoff 60 a scenario whose best control scores 55 is counted here, yet
    production backfills it (55 is above 0.42 x 60) and it publishes nearest-match controls capped
    at control_map_min_count, booked as `backfilled_count`."""
    from app.core.config import get_settings
    from app.pipeline.control_mapping import _backfill_floor

    rows = {t: empty for t, empty, _mean in sweep_relevance_thresholds(
        [_matches(55.0)] + [_matches(92.0)] * 19, top_k=5, thresholds=(50, 60))}
    assert (rows[50], rows[60]) == (0, 1)
    assert 55.0 >= _backfill_floor(60.0, get_settings()), (
        "the 55-scoring scenario the sweep calls stranded at 60 still publishes in production")


def test_modelling_the_backfill_would_recommend_the_top_of_the_sweep():
    """WHY the sweep deliberately does not model the backfill band, as a number rather than an
    assertion of taste. Count a scenario empty only when nothing reaches `ratio` x cutoff — the true
    "publishes controls: []" rule — and no realistic scenario is ever empty, so the recommendation
    walks to the top of the sweep. There it recommends a cutoff at which almost nothing CLEARS, every
    scenario is served by the backfill path, and the published list shrinks to the emergency floor
    (control_map_min_count) instead of the ceiling. The backfill is a floor under the damage of a
    cutoff set too high; it is not evidence that the cutoff may go higher."""
    ratio, min_count, max_count = 0.42, 5, 25
    results, best = _population(24, low=62.0, high=95.0)

    def published(matches, cutoff):
        """Production's whole rule: cutoff, then backfill to min_count above ratio x cutoff, cap."""
        cleared = [score for _row, score in matches if score >= cutoff]
        band = [score for _row, score in matches if ratio * cutoff <= score < cutoff]
        return min(max_count, len(cleared) + len(band[:max(0, min_count - len(cleared))]))

    counterfactual = [(t, sum(1 for ms in results if published(ms, t) == 0),
                    statistics.mean([published(ms, t) for ms in results]))
                    for t in DEFAULT_THRESHOLD_SWEEP]
    with_backfill, _stricter = recommend_relevance_cutoff(counterfactual, best)
    as_shipped, _stricter = recommend_relevance_cutoff(
        sweep_relevance_thresholds(results, top_k=max_count), best)
    assert with_backfill == max(DEFAULT_THRESHOLD_SWEEP), (
        "modelling the backfill leaves nobody empty at any swept threshold")
    assert as_shipped == 60
    means = dict((t, mean) for t, _empty, mean in counterfactual)
    assert means[with_backfill] <= min_count < means[as_shipped], (
        "the cutoff the backfill-modelled curve recommends is the one that shrinks every scenario's "
        "control list to the backfill floor")


# ---------------------------------------------------------------------------
# The percentile helper — report-facing only, and now actually nearest-rank
# ---------------------------------------------------------------------------

def test_percentile_is_nearest_rank_not_an_interpolated_position():
    """The function's NAME is the contract the operator report cites, and it used to compute
    `round(p/100 * (n - 1))` — the rounded linear-interpolation position, with Python's banker's
    rounding on the .5 boundary. p50 of [1,2,3,4] came back as 3.0, above BOTH the nearest-rank
    answer (2.0) and statistics.median (2.5), on the line the report labels "median". Nearest-rank
    is `ordered[ceil(p/100 * n) - 1]`: the smallest observed value at or below which at least p% of
    the sample sits, which for an even sample is the LOWER of the two middles."""
    assert percentile_nearest_rank([1.0, 2.0, 3.0, 4.0], 50) == 2.0
    assert percentile_nearest_rank([4.0, 1.0, 3.0, 2.0], 50) == 2.0        # sorts its input
    assert percentile_nearest_rank([1.0, 1.0, 1.0, 2.0], 50) == 1.0        # ties are values too
    assert percentile_nearest_rank(list(range(20)), 5) == 0.0              # rank ceil(1) = 1
    assert percentile_nearest_rank([float(x) for x in range(50, 100)], 5) == 52.0


def test_percentile_pins_its_boundaries():
    """p=0 and p=100 are the ends of the sample, never an IndexError from a rank of 0 or n+1, and a
    one-element sample answers every percentile. statistics.quantiles raises below n=2 and this
    measurement routinely runs on a handful of scenarios in a fresh environment."""
    assert percentile_nearest_rank([10.0, 20.0, 30.0], 0) == 10.0
    assert percentile_nearest_rank([10.0, 20.0, 30.0], 100) == 30.0
    assert percentile_nearest_rank([73.0], 5) == 73.0
    assert percentile_nearest_rank([73.0], 95) == 73.0
    assert percentile_nearest_rank([], 50) != percentile_nearest_rank([], 50)   # NaN, never a raise


def test_percentile_rank_never_goes_backwards_as_the_sample_grows():
    """Monotonicity of the RANK in n, over a NESTED sample (each n is the previous plus one larger
    observation) so that only the rank can move. `ceil(p/100 * n)` climbs by whole ranks and never
    steps back; the old `round(p/100 * (n - 1))` owed the same to banker's rounding rather than to a
    definition, and a reader "fixing" that rounding would have moved a reported number."""
    nested = [float(x) for x in range(120)]
    previous = -1.0
    for n in range(1, len(nested) + 1):
        value = percentile_nearest_rank(nested[:n], 5)
        assert value >= previous, n
        previous = value
    assert percentile_nearest_rank(nested[:20], 5) == 0.0     # rank ceil(1.00) = 1
    assert percentile_nearest_rank(nested[:21], 5) == 1.0     # rank ceil(1.05) = 2
    assert percentile_nearest_rank(nested[:40], 5) == 1.0     # rank ceil(2.00) = 2
    assert percentile_nearest_rank(nested[:41], 5) == 2.0     # rank ceil(2.05) = 3
