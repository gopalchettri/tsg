#!/usr/bin/env python
"""Measure the asset-context vs Threat_Catalogue rerank score distribution, then set
`TSG_THREAT_RELEVANCE_THRESHOLD` from what it reports.

WHY THIS EXISTS: the library-first funnel gates retrieved catalogue candidates on a rerank
score of asset/subsystem CONTEXT PROSE against threat names. That is a materially different
score distribution from the grounding calibration's name-vs-name paraphrases, so the
calibrated MatchTh does NOT transfer (the same label-vs-paragraph trap
`control_map_min_score` documents in config.py). A threshold set too high silently gates
every candidate into the flagged backfill pool and pushes every run to LLM generation — the
exact cost this funnel exists to eliminate; too low, and irrelevant CVEs ride in first-class.

So: don't eyeball the number, measure it. This script runs the REAL production path — the
same `threat_retrieval.retrieve_library_threats` Top-K funnel and the same
`threat_retrieval.score_relevance` rerank gate — against the REAL library and the REAL
stored session contexts, and prints what each candidate threshold would actually do.

    python scripts/measure_threat_relevance_scores.py             # recent sessions in the DB
    python scripts/measure_threat_relevance_scores.py --limit 10

WRITES IT MAKES — read this before pointing it at production. It never writes to SQL Server
(SELECTs only; the DB session is closed before the model calls begin). It DOES write to the
shared MongoDB embedding cache exactly the way a real run would: embedding the catalogue
passages goes through `embeddings.get_vectors`, which upserts any vector it had to compute.
On a warm cache that is zero documents; on a cold one it is one document per catalogue row —
a cache fill a real session would have performed anyway, not corruption.

Cost: the reranks plus the query embeddings for `--limit` sessions, plus the catalogue
embedding on a cold cache. The default limit is deliberately small.

Exit codes: 0 = measured, report printed · 2 = nothing to measure (no library, or no
sessions with stored context — run at least one real session first).
"""
from __future__ import annotations

import argparse
import json
import os
import statistics
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))  # make `app` importable

from sqlalchemy import select

from app.core.config import get_settings
from app.core.logging import configure_logging
from app.db import models as m
from app.db.engine import db_session
from app.pipeline import threat_retrieval
from app.pipeline.llm import get_llm

#: Thresholds the report walks. Wide on purpose — the point is to SEE where the cliff is.
_SWEEP = (0, 10, 20, 30, 40, 50, 55, 60, 65, 70, 75, 80, 85, 90, 95)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--limit", type=int, default=5,
                    help="sessions to measure, newest first (default 5)")
    args = ap.parse_args()
    configure_logging()
    s = get_settings()

    with db_session() as sess:
        sessions = sess.execute(
            select(m.Scenario_Session.SessionID, m.Scenario_Session.AssetName,
                m.Scenario_Session.SubsystemsJSON, m.Scenario_Session.AssetContextJSON)
            .order_by(m.Scenario_Session.CreatedAt.desc())
            .limit(args.limit)).all()
        contexts = []
        for sid, asset_name, subs_json, ctx_json in sessions:
            try:
                contexts.append((str(sid), asset_name,
                                json.loads(subs_json or "[]"),
                                json.loads(ctx_json or "{}")))
            except Exception:
                print(f"  ! session {sid}: unparseable stored context, skipped")
    if not contexts:
        print("Nothing to measure: no sessions with stored context. Run a session first.")
        return 2

    llm = get_llm()
    all_scores: list[float] = []
    print(f"top_k={s.threat_retrieval_top_k}  current threshold={s.threat_relevance_threshold}")
    for sid, asset_name, subsystems, asset_context in contexts:
        with db_session() as sess:
            candidates = threat_retrieval.retrieve_library_threats(
                sess, llm, subsystems, asset_context, session_id=sid)
        if not candidates:
            print(f"  session {sid} ({asset_name}): library returned nothing")
            continue
        scores = threat_retrieval.score_relevance(llm, candidates, subsystems,
                                                asset_context, s)
        vals = sorted(scores.values(), reverse=True)
        all_scores.extend(vals)
        top = ", ".join(f"{v:.1f}" for v in vals[:8])
        print(f"  session {sid} ({asset_name}): pool={len(candidates)} scored={len(vals)} "
            f"top scores: {top}")
    if not all_scores:
        print("Nothing to measure: no candidate scored (empty library or empty shortlists).")
        return 2

    all_scores.sort(reverse=True)
    print(f"\n{len(all_scores)} scored candidate readings across {len(contexts)} session(s)")
    print(f"  max={all_scores[0]:.1f}  median={statistics.median(all_scores):.1f}  "
        f"min={all_scores[-1]:.1f}")
    print("\nthreshold  pass first-class   flagged backfill-only")
    for th in _SWEEP:
        kept = sum(1 for v in all_scores if v >= th)
        print(f"   {th:5.1f}   {kept:6d} ({kept / len(all_scores):5.1%})"
            f"   {len(all_scores) - kept:6d}")
    print("\nPick the threshold where genuinely-relevant candidates stay first-class and the"
        "\nobviously-off-domain tail falls to backfill, then pin TSG_THREAT_RELEVANCE_THRESHOLD.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
