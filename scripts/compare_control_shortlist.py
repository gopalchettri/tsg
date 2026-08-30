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
from app.pipeline import control_mapping, embeddings, grounding, hybrid_search
from app.pipeline.llm import get_llm


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
        rows = sess.execute(text("""
            SELECT ts.ScenarioID, ts.ScenarioJSON, it.ThreatName, it.ThreatType
            FROM Threat_Scenario ts
            LEFT JOIN Scoped_Threat st ON st.ScopedThreatID = ts.ScopedThreatID
            LEFT JOIN Identified_Threat it ON it.ThreatID = st.ThreatID
            WHERE ts.SessionID = :sid AND ts.ScenarioJSON IS NOT NULL"""),
            {"sid": sid}).fetchall()
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
    queries = []
    for scenario_id, blob, tname, ttype in rows:
        q = control_mapping.collect_control_query(blob, tname, ttype)
        if q:
            queries.append((str(scenario_id), q))
    if not queries:
        print("no groundable scenarios in that session")
        return 2

    llm = get_llm()
    print(f"session {sid}  |  {len(queries)} scenarios  |  {len(candidates)} controls in pool")
    print(f"controls already mapped and stored: {sum(len(v) for v in stored.values())}\n")

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
