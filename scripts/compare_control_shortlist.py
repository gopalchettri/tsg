#!/usr/bin/env python
"""A/B the control shortlist: UNION (old) vs RRF (new), on your REAL scenarios and library.

WHY: switching the shortlist from "cosine top-k UNIONED with BM25 top-k" (up to 2k candidates)
to "the two legs RRF-fused to one ranked k" cuts cross-encoder pairs — the pipeline's dominant
cost — but it is still a recall question, and recall questions should not be settled by
arithmetic. This runs BOTH shortlists over the same stored scenarios and the same control
library and reports what actually differs.

It answers three things:
  1. how many cross-encoder pairs each strategy would produce (the cost);
  2. whether the controls ALREADY MAPPED and stored for those scenarios survive fusion — the
     recall check that matters, because those are the ones a reviewer can see today;
  3. how much narrower k would cost, if you pass more than one --k.

    python scripts/compare_control_shortlist.py                 # newest session with scenarios
    python scripts/compare_control_shortlist.py --session <id>
    python scripts/compare_control_shortlist.py --k 30 --k 15   # model both widths

THE QUERY MUST BE PRODUCTION'S, or this compares the wrong text. A shortlist width is only
meaningful for the query that is actually sent: both legs rank against it (BM25 tokenizes it, the
cosine leg embeds it), so measuring recall on a shorter string answers a question nobody asked.
This script used to own its own copy of the scenario SELECT and the per-row assembly, and that copy
drifted TWICE: first onto `control_mapping.collect_control_query`, a wrapper that drops the threat
category, the actors, the risk statement and all asset and system context; then onto a stale
positional call to `control_mapping._blob` after that helper gained a required keyword. Both drifts
needed the copy to exist, so it is gone. Queries now come from
`grounding.control_map_scenario_queries` — the one function the admin calibration route and
scripts/measure_control_map_scores.py also measure with, so none of the three can measure text the
others do not.

READ-ONLY against SQL Server (SELECTs only). It DOES populate the shared MongoDB embedding
cache through the normal embeddings path, exactly as a real run would — a cache fill, not a
mutation. It runs NO reranker, so it is cheap: the point is to compare the candidate sets that
would be SENT to the cross-encoder, not to re-score them.
"""
from __future__ import annotations

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy import text

from app.core.config import get_settings
from app.core.logging import configure_logging
from app.db.engine import db_session
from app.pipeline import embeddings, grounding, hybrid_search
from app.pipeline.llm import get_llm

#: `control_map_scenario_queries` takes a row limit because its other two callers sample the
#: newest N scenarios across the whole database. Here the SELECT is already narrowed to ONE
#: session, and a session holds at most _MAX_BATCH (50) subsystems' worth of scenarios, so this
#: is 'no limit' spelled as a number rather than a magic one that reads like a sample size.
_EVERY_SCENARIO_IN_THE_SESSION = 10_000


def _legs(llm, query: str, rows: list[dict], s, ck: int) -> tuple[list[int], list[int]]:
    """The two rankings as row indices, best-first — what ground_control_queries builds."""
    names = [r["text"] for r in rows]
    matrix_info = embeddings.get_matrix(llm, names, model_id=s.embedding_model,
                                        group="control_library", kind="passage")
    qv = llm.embed([query], kind="query")[0]
    sl = (grounding._shortlist_via_matrix(qv, rows, matrix_info, s, ck)
          if matrix_info is not None else None)
    if sl is None:
        vecs = embeddings.get_vectors(llm, names, model_id=s.embedding_model,
                                      group="control_library", kind="passage")
        sl = grounding._shortlist_candidates(qv, rows, vecs, "text", s, ck)
    idx_of = {id(r): i for i, r in enumerate(rows)}
    cos_rank = [idx_of[id(r)] for r in sl]
    docs_tokens = [hybrid_search.tokenize(r["text"]) for r in rows]
    kw_scores = hybrid_search.bm25_scores(hybrid_search.tokenize(query), docs_tokens)
    return cos_rank, hybrid_search._ranked_indices(kw_scores)[:ck]


def _union(cos_rank: list[int], kw_top: list[int]) -> list[int]:
    """The OLD behaviour: append the keyword leg's misses to the cosine leg. Up to 2*ck."""
    seen = set(cos_rank)
    return cos_rank + [i for i in kw_top if i not in seen]


def _rrf(cos_rank: list[int], kw_top: list[int], ck: int) -> list[int]:
    """The NEW behaviour: fuse both rankings, keep one ranked ck."""
    fused = hybrid_search.rrf_fuse([cos_rank, kw_top])
    return sorted(fused, key=lambda i: (-fused[i], i))[:ck]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--session", help="session id; default = newest session that has scenarios")
    ap.add_argument("--itot", action="append",
                    help="ITOT label(s) to narrow the control pool, matching what the real run "
                         "resolved (e.g. --itot OT). Omit to use the whole library.")
    ap.add_argument("--k", type=int, action="append",
                    help="shortlist width(s) to model; repeatable. Default: the configured value")
    args = ap.parse_args()
    configure_logging()
    s = get_settings()
    widths = args.k or [s.control_map_shortlist_k]

    with db_session() as sess:
        sid = args.session
        if not sid:
            sid = sess.execute(text("""
                SELECT TOP 1 ss.SessionID FROM Scenario_Session ss
                JOIN Threat_Scenario ts ON ts.SessionID = ss.SessionID
                GROUP BY ss.SessionID, ss.CreatedAt ORDER BY ss.CreatedAt DESC""")).scalar()
        if not sid:
            print("no session with scenarios found")
            return 2
        # The queries come from grounding.control_map_scenario_queries — the SAME function the admin
        # calibration route and measure_control_map_scores.py measure with. This script used to own a
        # THIRD copy of that SELECT and its per-row assembly, and the copy is the defect: the module
        # docstring records a copy that went on calling a builder the pipeline had moved off, so the
        # comparison ranked against a query production no longer sends. A leading threat identity is
        # worth 1.9 -> 60.6 on a real scenario — far more than the recall gap between the shortlist
        # widths this script exists to choose between, so the copy could have picked the wrong width
        # while looking rigorous. It then broke a SECOND time when control_mapping._blob gained a
        # required `column=` keyword and only the pipeline's own caller was updated.
        #
        # One behaviour change rides along with sharing, and it is a correction: the shared SELECT
        # excludes SUPERSEDED scenarios, where this copy filtered on ScenarioJSON IS NOT NULL alone.
        # A regenerated scenario's old version still owns map rows, so counting it measured recall
        # against a mapping production had already replaced.
        queries = grounding.control_map_scenario_queries(
            sess, _EVERY_SCENARIO_IN_THE_SESSION, s.max_embed_chars, session_id=sid)
        # What is mapped TODAY — the recall baseline a reviewer can already see on screen.
        stored: dict[str, set[int]] = {}
        for scenario_id, cid in sess.execute(text("""
                SELECT m.ScenarioID, m.ControlLibraryID FROM Threat_Scenario_Control_Map m
                JOIN Threat_Scenario ts ON ts.ScenarioID = m.ScenarioID
                WHERE ts.SessionID = :sid"""), {"sid": sid}):
            stored.setdefault(str(scenario_id), set()).add(int(cid))
        # The pool MUST match production or the comparison measures a run that never happens.
        # map_controls narrows by the session's resolved ITOT labels (controls.mapped logged
        # itot_labels=["OT"] for these sessions), so comparing against all 1288 controls makes
        # every shortlist fight competition the real run never sees — which is pessimistic for
        # whichever strategy is narrower. --itot reproduces the real pool.
        candidates = grounding.get_control_candidates(sess, args.itot or None)

    if not candidates:
        print("control library returned no candidates — nothing to compare")
        return 2
    if not queries:
        print("no groundable scenarios in that session")
        return 2

    llm = get_llm()
    print(f"session {sid}  |  {len(queries)} scenarios  |  {len(candidates)} controls in pool")
    print(f"controls already mapped and stored: {sum(len(v) for v in stored.values())}")
    # Printed, not claimed: both legs rank against this exact string, so an operator reading a
    # recall number is entitled to see the text it was measured on.
    print("query: production's own (grounding.control_map_scenario_queries), e.g.")
    print(f"  [{queries[0][0][:8]}] {queries[0][1][:200]}\n")

    for ck in widths:
        u_pairs = r_pairs = kept = lost = 0
        lost_detail: list[str] = []
        for scenario_id, q in queries:
            cos_rank, kw_top = _legs(llm, q, candidates, s, ck)
            u = _union(cos_rank, kw_top)
            r = _rrf(cos_rank, kw_top, ck)
            u_pairs += len(u)
            r_pairs += len(r)
            rrf_ids = {candidates[i]["ControlLibraryID"] for i in r}
            for cid in sorted(stored.get(scenario_id, set())):
                if cid in rrf_ids:
                    kept += 1
                else:
                    lost += 1
                    lost_detail.append(f"scenario {scenario_id[:8]} -> control {cid}")
        saved = (1 - r_pairs / u_pairs) * 100 if u_pairs else 0.0
        print(f"--- shortlist_k = {ck} ---")
        print(f"  cross-encoder pairs   UNION {u_pairs:5d}    RRF {r_pairs:5d}"
              f"    ({saved:.0f}% fewer)")
        if stored:
            total = kept + lost
            print(f"  already-mapped controls still shortlisted by RRF: {kept}/{total}")
            for d in lost_detail[:10]:
                print(f"      LOST  {d}")
            if lost > 10:
                print(f"      ... and {lost - 10} more")
        print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
