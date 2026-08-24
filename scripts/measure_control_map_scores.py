#!/usr/bin/env python
"""Measure the scenario-paragraph vs Control_Library score distribution, then set
`TSG_CONTROL_MAP_MIN_SCORE` from what it reports.

WHY THIS EXISTS: Step-4 control mapping used to query the library with the MODEL'S OWN short
control labels ("Multi-Factor Authentication"). The library-first redesign replaced that with the
scenario's own PARAGRAPH — title + statement, a hundred words of prose. Label-vs-label and
paragraph-vs-label are materially different score distributions, and `control_map_min_score` is
left unset by default, which makes it fall back to the grounding threshold auto-calibrated on the
OLD shape.

The failure that creates is silent and expensive. A cutoff set too high drops every match, every
scenario returns `controls: []`, and the API documents that exact state as a healthy LIBRARY GAP
("mapping ran and nothing matched"). Nothing errors. Nothing logs. A reviewer sees an assessment
with no recommended controls and reasonably concludes the library does not cover their asset.

So: don't eyeball the number, measure it. This script runs the REAL production path — the same
`grounding.get_control_candidates`, the same hybrid shortlist, the same reranker, the same
`control_mapping.collect_control_query` — against the REAL library, and prints what each candidate
threshold would actually do.

    python scripts/measure_control_map_scores.py                       # use real scenarios in the DB
    python scripts/measure_control_map_scores.py --limit 200
    python scripts/measure_control_map_scores.py --text-file paras.txt # pre-first-session
    python scripts/measure_control_map_scores.py --itot OT             # narrow the library

READ-ONLY. It opens a session, SELECTs, and never writes — safe against production. It does call
the embedding and reranker models, which costs whatever your provider charges for `--limit`
embeddings plus the reranks; the default limit is deliberately small.

`--text-file` takes one scenario paragraph per line, for an environment that has the control
library seeded but has not run a session yet. Use real prose, not labels: feeding it short
control-shaped strings reproduces the very bias this script exists to detect.

Exit codes: 0 = measured, report printed · 2 = nothing to measure (no library, no scenarios and
no --text-file, or empty shortlists — a retrieval fault, not a threshold one).
"""
from __future__ import annotations

import argparse
import os
import statistics
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))  # make `app` importable

from sqlalchemy import select

from app.core.config import get_settings
from app.core.logging import configure_logging
from app.db import models as m
from app.db.engine import db_session
from app.pipeline import control_mapping, grounding
from app.pipeline.llm import get_llm

#: Thresholds the report walks. Wide on purpose — the point is to SEE where the cliff is, and a
#: narrow sweep around today's value would hide a cliff sitting just outside it.
_SWEEP = (0, 10, 20, 30, 40, 50, 55, 60, 65, 70, 75, 80, 85, 90, 95)


def _pct(values: list[float], p: float) -> float:
    """Nearest-rank percentile. Not statistics.quantiles: that interpolates and needs n >= 2,
    and this runs on samples as small as a handful of scenarios."""
    if not values:
        return float("nan")
    ordered = sorted(values)
    idx = min(len(ordered) - 1, max(0, round(p / 100.0 * (len(ordered) - 1))))
    return ordered[idx]


def sweep(results: list[list[tuple[dict, float]]], top_k: int,
        thresholds: tuple[int, ...] = _SWEEP) -> list[tuple[int, int, float]]:
    """(threshold, scenarios that would publish ZERO controls, mean controls per scenario).

    `empty` is the number that matters: those scenarios publish `controls: []`, which the API
    documents as a healthy library gap, so they are the silent failure this whole script exists
    to price. Capped at top_k because production caps there — counting uncapped matches would
    overstate what a threshold actually delivers."""
    rows = []
    for t in thresholds:
        kept = [min(top_k, sum(1 for _row, score in matches if score >= t))
                for matches in results]
        rows.append((t, sum(1 for k in kept if k == 0),
                    statistics.mean(kept) if kept else 0.0))
    return rows


def recommend(rows: list[tuple[int, int, float]], best: list[float]) -> tuple[int | None, float]:
    """(safe threshold, stricter alternative).

    Safe = the HIGHEST swept value at which no scenario loses all its controls. None when even
    0 leaves scenarios empty, which means their shortlists were empty and the fault is in
    retrieval, not the cutoff — a threshold recommendation there would be noise dressed as an
    answer. The stricter alternative trades ~5% of scenarios going empty for a cleaner tail;
    it is offered, never chosen here, because that trade is the operator's to make."""
    safe = max((t for t, empty, _mean in rows if empty == 0), default=None)
    return safe, _pct(best, 5)


def _queries_from_db(sess, limit: int) -> list[tuple[str, str]]:
    """(label, query) from real completed scenarios, built with the SAME query builder
    production uses — a hand-rolled "title + statement" here would measure a query shape the
    pipeline never actually sends."""
    rows = sess.execute(
        select(m.Threat_Scenario_Output.OutputID, m.Threat_Scenario_Output.ScenarioJSON)
        .where(m.Threat_Scenario_Output.Status == "complete",
            m.Threat_Scenario_Output.Superseded == 0,
            m.Threat_Scenario_Output.ScenarioJSON.is_not(None))
        .order_by(m.Threat_Scenario_Output.CreatedAt.desc())
        .limit(limit)
    ).all()
    out = []
    for output_id, scenario_json in rows:
        query = control_mapping.collect_control_query(scenario_json)
        if query:
            out.append((str(output_id)[:8], query))
    return out


def _queries_from_file(path: str, limit: int) -> list[tuple[str, str]]:
    with open(path, encoding="utf-8") as fh:
        lines = [ln.strip() for ln in fh if ln.strip()]
    return [(f"line{i + 1}", ln) for i, ln in enumerate(lines[:limit])]


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--limit", type=int, default=50,
                    help="scenarios/paragraphs to measure (default 50)")
    ap.add_argument("--text-file", help="one scenario paragraph per line, instead of DB scenarios")
    ap.add_argument("--itot", choices=["IT", "OT"], help="narrow the library, as a real session would")
    args = ap.parse_args()

    configure_logging()
    s = get_settings()
    llm = get_llm()

    with db_session() as sess:
        candidates = grounding.get_control_candidates(sess, args.itot)
        if not candidates:
            print("FAIL  Control_Library returned no active rows — run Seed_to_Control_library.sql "
                "first. Measuring against an empty library would 'prove' any threshold.")
            return 2
        queries = (_queries_from_file(args.text_file, args.limit) if args.text_file
                else _queries_from_db(sess, args.limit))
        if not queries:
            print("FAIL  no scenario text to measure. Run one session first, or pass --text-file "
                "with real scenario paragraphs (NOT short control labels — that reproduces the "
                "exact bias this script exists to detect).")
            return 2

        auto = grounding.resolve_thresholds(sess, llm, s)
        explicit = "control_map_min_score" in s.model_fields_set
        in_force = s.control_map_min_score if explicit else auto.value
        # Read the provenance rather than inferring it. The three origins collide numerically,
        # so "75.0" alone cannot tell a measurement from a default meant for another model pair.
        origin = "TSG_CONTROL_MAP_MIN_SCORE, operator-pinned" if explicit else {
            "env_pinned": "TSG_GROUNDING_MATCH_THRESHOLD, operator-pinned",
            "calibrated": "auto-calibrated for THIS embedding+reranker pair",
            "static_default": ("the static Settings default - tuned for a DIFFERENT model pair, "
                            "and never measured for paragraph-vs-label. NOT evidence"),
        }.get(auto.origin, auto.origin)

        print(f"library         {len(candidates)} active controls"
            + (f" (ITOT={args.itot})" if args.itot else ""))
        print(f"queries         {len(queries)} "
            + ("scenario paragraphs from --text-file" if args.text_file
                else "real scenarios from the DB"))
        print(f"models          embed={s.embedding_model}  rerank={s.reranker_model}")
        print(f"shortlist_k     {s.grounding_shortlist_k}   top_k={s.control_map_top_k}")
        print(f"threshold NOW   {in_force:.1f}   ({origin})")
        print()

        # The production call, unmodified: one query per scenario, full reranked shortlist back.
        results = grounding.ground_control_queries(llm, [(q, None) for _, q in queries],
                                                candidates, s)

    # --- per-query score shape ------------------------------------------------------------
    # ControlMatches.answered separates "we reranked and nothing scored" (a real data point)
    # from "we never got an answer" (a failed rerank item — not a measurement). Folding the
    # second into the first would inflate the "0 controls" column at EVERY threshold and, with
    # one provider blip, suppress the recommendation entirely while blaming retrieval.
    measured = [r.matches for r in results if r.answered]
    unanswered = len(results) - len(measured)
    best: list[float] = []
    at_k: list[float] = []
    shortlist_sizes: list[int] = []
    for matches in measured:
        scores = [score for _row, score in matches]
        shortlist_sizes.append(len(scores))
        if scores:
            best.append(scores[0])
            at_k.append(scores[min(s.control_map_top_k, len(scores)) - 1])

    if unanswered:
        print(f"NOTE  {unanswered} of {len(results)} queries never got an answer (their rerank "
            "item failed — look for rerank_many.item_failed). EXCLUDED from everything below "
            "rather than counted as 'no controls'; re-run if this number is not 0.")
        print()
    if not best:
        print("FAIL  every measured query came back with an empty shortlist — that is a "
            "retrieval problem, not a threshold one. Confirm the control_library embedding "
            "group is populated (scripts/refresh_embeddings.py --group control_library) "
            "before reading anything below.")
        return 2

    print("SCORE DISTRIBUTION  (reranker score, 0-100)")
    print(f"  best match per scenario      p05 {_pct(best, 5):6.1f}   p25 {_pct(best, 25):6.1f}   "
        f"median {_pct(best, 50):6.1f}   p95 {_pct(best, 95):6.1f}")
    print(f"  #{s.control_map_top_k} match per scenario        p05 {_pct(at_k, 5):6.1f}   "
        f"p25 {_pct(at_k, 25):6.1f}   median {_pct(at_k, 50):6.1f}   p95 {_pct(at_k, 95):6.1f}")
    print(f"  shortlist size               min {min(shortlist_sizes)}  "
        f"median {statistics.median(shortlist_sizes):.0f}  max {max(shortlist_sizes)}")
    print()

    # --- what each threshold would actually DO ---------------------------------------------
    # The only number that matters for the silent-failure risk is `empty`: scenarios that would
    # publish controls: [] and be read as a healthy library gap.
    print(f"WHAT EACH THRESHOLD WOULD DO  ({len(measured)} measured scenarios, capped at "
        f"top_k={s.control_map_top_k})")
    print("  threshold   scenarios with 0 controls   mean controls/scenario")
    rows = sweep(measured, s.control_map_top_k)
    for t, empty, mean_kept in rows:
        print(f"  {t:>9}   {empty:>25}   {mean_kept:>21.2f}")
    # The in-force value gets its OWN line, evaluated at the real float. Flagging the nearest
    # swept row instead left dead bands (nothing within 2.5 of, say, 35.0), and when the flag
    # missed, the single most decision-relevant number silently vanished from the report.
    in_force_empty = sum(1 for ms in measured if not any(sc >= in_force for _r, sc in ms))
    print(f"  {in_force:>9.1f}   {in_force_empty:>25}   {'':>21}  <-- IN FORCE NOW")
    print()

    # --- the recommendation -----------------------------------------------------------------
    strict, p05_based = recommend(rows, best)
    print("RECOMMENDATION")
    if strict is None:
        print("  Even a threshold of 0 leaves scenarios with no controls, which means their "
            "shortlists were empty. Fix retrieval before tuning the cutoff.")
    else:
        print(f"  TSG_CONTROL_MAP_MIN_SCORE={strict}")
        print("    The highest swept value at which NO scenario loses all its controls — safe by "
            "construction against the silent-empty failure.")
        print(f"  Stricter alternative: {p05_based:.0f} (5th percentile of best-match scores), "
            "which accepts ~5% of scenarios going empty in exchange for a cleaner tail.")
    print()
    print(f"  The value IN FORCE ({in_force:.1f}) comes from: {origin}.")
    print(f"  At it, {in_force_empty} of {len(measured)} scenarios publish NO controls - "
        "which the API reports as a healthy library gap, not as a mis-set cutoff.")
    if not explicit:
        print("  Set TSG_CONTROL_MAP_MIN_SCORE explicitly either way: an unset knob here is "
            "an undocumented dependency on a number derived for a different question.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
