"""Pins the decision math in scripts/measure_control_map_scores.py.

The script itself needs a live database and real models, so it cannot run in CI — but the part
an operator ACTS on is pure: given per-scenario match scores, which threshold does it recommend?
A wrong answer there is set into TSG_CONTROL_MAP_MIN_SCORE by hand and then silently empties
every scenario's control list, which the API reports as a healthy library gap. So the math is
tested here even though the I/O around it cannot be.
"""
import importlib.util
from pathlib import Path

_SPEC = importlib.util.spec_from_file_location(
    "measure_control_map_scores",
    Path(__file__).resolve().parents[1] / "scripts" / "measure_control_map_scores.py")
mod = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(mod)


def _matches(*scores):
    """One scenario's reranked shortlist; the row payload is irrelevant to the math."""
    return [({}, s) for s in scores]


def test_sweep_counts_empties_and_caps_at_top_k():
    results = [_matches(95.0, 80.0, 40.0), _matches(50.0, 45.0)]
    rows = {t: (empty, mean) for t, empty, mean in mod.sweep(results, top_k=2,
                                                            thresholds=(0, 60, 90))}
    # at 0 both scenarios keep matches, but CAPPED at top_k=2 — not 3 and 2
    assert rows[0] == (0, 2.0)
    # at 60 only the first scenario has anything left
    assert rows[60] == (1, 1.0)
    # at 90 one match survives in total, so one scenario is empty and the mean is 0.5
    assert rows[90] == (1, 0.5)


def test_recommend_picks_the_highest_threshold_that_empties_nobody():
    results = [_matches(95.0, 80.0), _matches(70.0, 65.0), _matches(62.0)]
    rows = mod.sweep(results, top_k=5, thresholds=(0, 50, 60, 65, 70))
    safe, _stricter = mod.recommend(rows, [95.0, 70.0, 62.0])
    # 60 keeps every scenario; 65 would empty the third (its best match is 62)
    assert safe == 60


def test_recommend_refuses_when_even_zero_leaves_scenarios_empty():
    """An empty shortlist is a RETRIEVAL fault — the embedding group is unpopulated, say. No
    threshold fixes it, so the script must not hand back a number that looks like a fix."""
    results = [_matches(90.0), []]
    rows = mod.sweep(results, top_k=5, thresholds=(0, 50))
    safe, _stricter = mod.recommend(rows, [90.0])
    assert safe is None


def test_stricter_alternative_is_the_5th_percentile_of_best_matches():
    best = [float(x) for x in range(50, 100)]        # 50..99
    _safe, stricter = mod.recommend(mod.sweep([], top_k=5), best)
    assert stricter == 52.0                          # nearest-rank p05 of 50 values


def test_percentile_survives_a_one_element_sample():
    """statistics.quantiles raises below n=2; this script routinely runs on a handful of
    scenarios in a fresh environment, so the percentile must degrade rather than crash."""
    assert mod._pct([73.0], 5) == 73.0
    assert mod._pct([73.0], 95) == 73.0
    assert mod._pct([], 50) != mod._pct([], 50)      # NaN, and never an exception
