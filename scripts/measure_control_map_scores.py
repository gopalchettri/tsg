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
`control_mapping._retrieval_query` — against the REAL library, and prints what each candidate
threshold would actually do.

MEASURED DEFECT IN THIS INSTRUMENT, not in the pipeline: DB mode used to build its queries with
`control_mapping.collect_control_query`, a wrapper that existed only for these two scripts and has since been deleted, which emits
threat type + name + scenario title + statement and nothing else. Control mapping had meanwhile
moved to `control_relevance.build_control_retrieval_query` (reached through
`control_mapping._retrieval_query`), whose query LEADS with the threat category and also carries
the threat actors, the risk statement, the asset name + technology and the involved supporting
systems — a leading threat identity is worth 1.9 -> 60.6 on a real scenario, so the two strings
score nothing alike. The instrument was therefore measuring a query production no longer sends,
and a cutoff re-pinned from it would have been mis-calibrated: the exact silent failure this
script exists to prevent, reintroduced through the measuring instrument. The copy then broke a
SECOND time when `control_mapping._blob` gained a required `column=` keyword and only the pipeline's
own caller was updated. Both drifts needed that second copy to exist, so it is GONE: DB mode calls
`grounding.control_map_scenario_queries`, the same function the admin calibration route measures
with, so the script and the route cannot measure different text and a signature change reaches this
file through the suite. It still prints which builder it used and one real query, so parity can be
read rather than trusted.

    python scripts/measure_control_map_scores.py                       # use real scenarios in the DB
    python scripts/measure_control_map_scores.py --limit 200
    python scripts/measure_control_map_scores.py --text-file paras.txt # pre-first-session
    python scripts/measure_control_map_scores.py --itot OT             # narrow the library

WRITES IT MAKES — read this before pointing it at production. It never writes to SQL Server
(SELECTs only, and the DB session is closed before the model calls begin). It DOES write to the
shared MongoDB embedding cache: embedding the control library goes through the same
`embeddings.get_vectors` path production uses, which upserts any vector it had to compute into
the `embeddings` collection (embeddings.py::_l2_write) and creates that collection's unique
index on first touch. On a warm cache that is zero documents; on a COLD cache it is one document
per control (~1288). Those documents are exactly what a real session would have written anyway
— a cache fill, not corruption — but "READ-ONLY, never writes" was the wrong claim, and an
earlier version of this docstring made it.

Cost: the reranks plus the query embeddings for `--limit` scenarios, plus the library embedding
on a cold cache (batched at embedding_batch_size by llm.embed, and `--limit` does NOT bound that
part). The default limit is deliberately small.

`--text-file` takes one scenario paragraph per line, for an environment that has the control
library seeded but has not run a session yet. Use real prose, not labels: feeding it short
control-shaped strings reproduces the very bias this script exists to detect. It measures a
NARRATIVE-ONLY query by design — there is no threat, asset or system context before the first
session — so its scores are systematically different from a session's and the header says so.

Exit codes: 0 = measured, report printed · 2 = nothing to measure (no library, no scenarios and
no --text-file, or empty shortlists — a retrieval fault, not a threshold one).
"""
from __future__ import annotations

import argparse
import os
import statistics
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))  # make `app` importable


from app.core.config import get_settings
from app.core.logging import configure_logging
from app.db.engine import db_session
from app.pipeline import grounding
from app.pipeline.control_threshold import (
    percentile_nearest_rank,
    recommend_relevance_cutoff,
    sweep_relevance_thresholds,
)
from app.pipeline.llm import get_llm

# The sweep + recommendation maths used to live HERE. It moved to app/pipeline/control_threshold.py
# unchanged, because the application now runs this measurement too (an admin route stores the
# result) and two copies of a decision rule is exactly the drift this script's own docstring is a
# monument to. Read that module before acting on `stricter`: it is offered, not chosen.


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
    ap.add_argument("--itot", help="narrow the library to one ITOT label, as a real session "
                    "would (checked against the live Control_Library vocabulary after connecting)")
    args = ap.parse_args()

    configure_logging()
    s = get_settings()
    llm = get_llm()

    with db_session() as sess:
        itot_labels = None
        if args.itot:
            live_vocab = grounding.control_itot_vocabulary(sess)
            if args.itot not in live_vocab:
                print(f"FAIL  --itot {args.itot!r} is not a label the active Control_Library "
                    f"carries today (live values: {sorted(live_vocab) or '(none)'}).")
                return 2
            itot_labels = [args.itot]
        candidates = grounding.get_control_candidates(sess, itot_labels)
        if not candidates:
            print("FAIL  Control_Library returned no active rows — run Seed_to_Control_library.sql "
                "first. Measuring against an empty library would 'prove' any threshold.")
            return 2
        # DB mode calls the SAME function the admin calibration route measures with, so the two can
        # never measure different text. This script used to own a private copy of that SELECT and its
        # per-row assembly. The module docstring above is a monument to what a second copy costs: the
        # copy went on calling a builder the pipeline had moved off, so the instrument measured a
        # query production no longer sends — and a leading threat identity is worth 1.9 -> 60.6 on a
        # real scenario, so a cutoff re-pinned from it was mis-calibrated. That is the very silent
        # failure this script exists to prevent, reintroduced through the measuring instrument. The
        # copy then broke a SECOND time in the same week: control_mapping._blob gained a required
        # `column=` keyword and only the pipeline's own caller was updated. Sharing the function
        # makes a signature change reach this file through the suite instead of at an operator's
        # prompt, and `grounding` owns it because the APPLICATION runs this measurement too.
        queries = (_queries_from_file(args.text_file, args.limit) if args.text_file
                else grounding.control_map_scenario_queries(sess, args.limit, s.max_embed_chars))
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
            "env_pinned": "TSG_GROUNDING_MATCH_THRESHOLD bootstrap (no calibration stored yet)",
            "calibrated": "auto-calibrated for THIS embedding+reranker pair",
            "static_default": ("the static Settings default - tuned for a DIFFERENT model pair, "
                            "and never measured for paragraph-vs-label. NOT evidence"),
        }.get(auto.origin, auto.origin)

        print(f"library         {len(candidates)} active controls"
            + (f" (ITOT={args.itot})" if args.itot else ""))
        print(f"queries         {len(queries)} "
            + ("scenario paragraphs from --text-file" if args.text_file
                else "real scenarios from the DB"))
        # WHICH QUERY WAS MEASURED, stated rather than assumed. A threshold is only transferable to
        # production if the text it was measured on is production's text, and the two modes differ
        # on exactly that — so the mode, the builder and one real query are all printed, and an
        # operator can check parity instead of trusting this script's word for it.
        if args.text_file:
            print("query shape     NARRATIVE ONLY (--text-file mode): no threat category, type or "
                "name, no actors, no risk statement, no asset or system context. Production leads "
                "its query with the threat identity, so these scores are systematically DIFFERENT "
                "from a session's — treat the recommendation as provisional until re-measured "
                "from real scenarios.")
        else:
            print("query shape     production's own, via control_mapping._retrieval_query -> "
                "control_relevance.build_control_retrieval_query: threat category, type, name "
                "(library spelling preferred), actors, scenario title, statement, risk statement, "
                "asset name + technology, involved systems. No production input is withheld.")
        sample_label, sample_query = queries[0]
        print(f"query sample    [{sample_label}] {sample_query[:240]}"
            + ("..." if len(sample_query) > 240 else ""))
        print(f"models          embed={s.embedding_model}  rerank={s.reranker_model}")
        print(f"shortlist_k     {s.grounding_shortlist_k}   min_count={s.control_map_min_count}   "
            f"max_count={s.control_map_max_count}")
        print(f"threshold NOW   {in_force:.1f}   ({origin})")
        print()

    # --- everything below is OUTSIDE the DB session, deliberately -------------------------
    # The rerank + embed calls take minutes. Running them inside the `with db_session()` block
    # held an open SQL Server transaction open for that whole time, against the same instance a
    # live pipeline is using — a measurement script must not be the thing that blocks the system
    # it is measuring. Everything needed below (`candidates`, `queries`, thresholds) is already
    # materialised in memory.

    # Prime the query vectors in ONE deduped call, exactly as control_mapping.map_controls does
    # (llm.embed chunks to the provider's per-request cap internally). Passing None per query
    # instead makes ground_control_queries embed them ONE HTTP CALL AT A TIME, which is both far
    # slower and no longer "the production call unmodified" — the shape being measured would
    # differ from the shape production sends.
    texts = list(dict.fromkeys(q for _label, q in queries))
    qv_map: dict[str, list[float]] = {}
    try:
        qv_map.update(zip(texts, llm.embed(texts, kind="query")))
    except Exception as exc:  # noqa: BLE001 — degrade exactly as production does
        print(f"NOTE  query-vector priming failed ({exc!r}); falling back to per-query embedding, "
            "same as production's own except-branch. Scores are unaffected.")

    # The production call: one query per scenario, full reranked shortlist back.
    results = grounding.ground_control_queries(
        llm, [(q, qv_map.get(q)) for _label, q in queries], candidates, s)

    # --- per-query score shape ------------------------------------------------------------
    # ControlMatches.answered separates "we reranked and nothing scored" (a real data point)
    # from "we never got an answer" (a failed rerank item — not a measurement). Folding the
    # second into the first would inflate the "0 controls" column at EVERY threshold and, with
    # one provider blip, suppress the recommendation entirely while blaming retrieval.
    # Labels ride along. control_map_scenario_queries/_queries_from_file both return (label, query) and the
    # report used to throw the label away, so it could say "3 scenarios publish no controls"
    # without being able to name ONE of them — leaving the operator to go find them by hand.
    measured_pairs = [(label, r.matches)
                    for (label, _q), r in zip(queries, results) if r.answered]
    measured = [ms for _label, ms in measured_pairs]
    unanswered = len(results) - len(measured)
    best: list[float] = []
    at_k: list[float] = []
    shortlist_sizes: list[int] = []
    for matches in measured:
        scores = [score for _row, score in matches]
        shortlist_sizes.append(len(scores))
        if scores:
            best.append(scores[0])
            # The MINIMUM, not the ceiling: this measures "what does the Nth best control score",
            # which is what a cutoff has to clear for a scenario to reach its minimum. Reading the
            # ceiling (25) here instead of the minimum (5) would answer a question nobody asks and
            # push the recommended cutoff far too low.
            at_k.append(scores[min(s.control_map_min_count, len(scores)) - 1])

    if unanswered:
        print(f"NOTE  {unanswered} of {len(results)} queries never got an answer (their rerank "
            "item failed — look for rerank_many.item_failed). EXCLUDED from everything below "
            "rather than counted as 'no controls'; re-run if this number is not 0.")
        print()
    if not best:
        # Two different faults, two different fixes — the old single message blamed retrieval
        # for both, sending an operator to re-embed a library that was fine.
        if not measured:
            print(f"FAIL  none of the {len(results)} queries got an answer at all — every rerank "
                "item failed. That is a MODEL/PROVIDER fault, not retrieval and not the "
                "threshold. Check the reranker endpoint and rerank_many.item_failed, then "
                "re-run; nothing below could be measured.")
        else:
            print("FAIL  every measured query came back with an empty shortlist — that is a "
                "retrieval problem, not a threshold one. Confirm the control_library embedding "
                "group is populated (scripts/refresh_embeddings.py --group control_library) "
                "before reading anything below.")
        return 2

    print("SCORE DISTRIBUTION  (reranker score, 0-100)")
    print(f"  best match per scenario      p05 {percentile_nearest_rank(best, 5):6.1f}   "
        f"p25 {percentile_nearest_rank(best, 25):6.1f}   "
        f"median {percentile_nearest_rank(best, 50):6.1f}   "
        f"p95 {percentile_nearest_rank(best, 95):6.1f}")
    print(f"  #{s.control_map_min_count} match per scenario        "
        f"p05 {percentile_nearest_rank(at_k, 5):6.1f}   "
        f"p25 {percentile_nearest_rank(at_k, 25):6.1f}   "
        f"median {percentile_nearest_rank(at_k, 50):6.1f}   "
        f"p95 {percentile_nearest_rank(at_k, 95):6.1f}")
    print(f"  shortlist size               min {min(shortlist_sizes)}  "
        f"median {statistics.median(shortlist_sizes):.0f}  max {max(shortlist_sizes)}")
    print()

    # --- what each threshold would actually DO ---------------------------------------------
    # The only number that matters for the silent-failure risk is `empty`: scenarios that would
    # publish controls: [] and be read as a healthy library gap.
    print(f"WHAT EACH THRESHOLD WOULD DO  ({len(measured)} measured scenarios, minimum "
        f"{s.control_map_min_count}, ceiling {s.control_map_max_count})")
    print("  threshold   scenarios with 0 controls   mean controls/scenario")
    rows = sweep_relevance_thresholds(measured, s.control_map_max_count)
    for t, empty, mean_kept in rows:
        print(f"  {t:>9}   {empty:>25}   {mean_kept:>21.2f}")
    # The in-force value gets its OWN line, evaluated at the real float. Flagging the nearest
    # swept row instead left dead bands (nothing within 2.5 of, say, 35.0), and when the flag
    # missed, the single most decision-relevant number silently vanished from the report.
    empty_now = [label for label, ms in measured_pairs
                if not any(sc >= in_force for _r, sc in ms)]
    in_force_empty = len(empty_now)
    print(f"  {in_force:>9.1f}   {in_force_empty:>25}   {'':>21}  <-- IN FORCE NOW")
    if empty_now:
        # Named, not just counted: these are the exact scenarios publishing `controls: []`
        # today, so the operator can open one and judge whether the library really has nothing
        # for it — the one check that tells a mis-set cutoff from a genuine gap.
        shown = ", ".join(empty_now[:12])
        more = f" (+{len(empty_now) - 12} more)" if len(empty_now) > 12 else ""
        print(f"      publishing NO controls at {in_force:.1f}: {shown}{more}")
    print()

    # --- the recommendation -----------------------------------------------------------------
    safe, p05_based = recommend_relevance_cutoff(rows, best)
    print("RECOMMENDATION")
    if safe is None:
        print("  Even a threshold of 0 leaves scenarios with no controls, which means their "
            "shortlists were empty. Fix retrieval before tuning the cutoff.")
    else:
        print(f"  TSG_CONTROL_MAP_MIN_SCORE={safe}")
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
