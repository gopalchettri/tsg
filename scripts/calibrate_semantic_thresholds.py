"""Measure the semantic-dedup cosine landscape on WHATEVER embedder this environment configures.

The dedup bar (`semantic_cross_category_threshold`, default 0.98) was measured on local
e5-large@1024. Cosine distributions are EMBEDDING-MODEL-SPECIFIC — config.py's own comment says
an e5 value "means nothing on qwen3-8b@4096" — so any environment with a different embedder
(e.g. UAT: EMBEDDING_PROVIDER=litellm_proxy, TSG_EMBEDDING_MODEL=qwen3-embedding-8b-mig) must
re-measure before trusting "unique in meaning".

Run:  python scripts/calibrate_semantic_thresholds.py
(uses the environment's .env — run it IN the target environment, not about it)

Reads nothing from the DB and writes nothing anywhere: it embeds a fixed pair list through
llm.embed (the same client the dedup scan uses), prints one cosine per pair, and suggests
bar = highest DISTINCT cosine + safety margin. NOT a paraphrase/distinct midpoint: the two
classes overlap by nature (measured on e5: the disclosure/modification trap at 0.9689 sits
ABOVE paraphrases at 0.927-0.967), and the design rule is asymmetric — merging two DISTINCT
threats is forbidden, letting a paraphrase survive is tolerated. So the bar clears every known
distinct pair and catches whatever restatements sit above it. The operator then sets, in THAT
environment's env config:

    TSG_SEMANTIC_CROSS_CATEGORY_THRESHOLD=<suggested bar>

Self-check: run locally (e5-large@1024) the suggestion reproduces the shipped 0.98 default
(0.9689 + 0.01 ≈ 0.979). Rerun this script on every embedder change.
"""
from __future__ import annotations

import math
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.core.config import get_settings
from app.pipeline.llm import get_llm

# Each entry: (label_a, label_b, is_paraphrase). Labels are asset-stripped, mirroring
# _semantic_duplicates' comparison input. The e5-large@1024 reference numbers are in comments —
# reproducing them locally is this script's own self-check.
PAIRS: list[tuple[str, str, bool]] = [
    # True paraphrases — same meaning, different words (e5: >= ~0.92)
    ("Data leakage of operational records", "Unauthorised disclosure of operational records", True),
    ("Unavailability of control functions", "Loss of control functions", True),
    ("Manipulation of audit logs", "Tampering with audit logs", True),
    ("Unauthorized disclosure of authentication credentials",
     "Theft of authentication credentials", True),
    # The measured trap — two REAL threats one word apart (e5: 0.969, must stay BELOW the bar)
    ("Unauthorized disclosure of operational data", "Unauthorized modification of operational data", False),
    # Genuinely distinct — same asset domain, different meaning (e5: well below 0.92)
    ("Unauthorized disclosure of operational data", "Denial of service against control functions", False),
    ("Suppression of alarms and trip signals", "Theft of authentication credentials", False),
    ("Spoofed shutdown commands accepted", "Loss of backup and restore capability", False),
]


def _cos(a: list[float], b: list[float]) -> float:
    na = math.sqrt(sum(x * x for x in a)) or 1.0
    nb = math.sqrt(sum(x * x for x in b)) or 1.0
    return sum(x * y for x, y in zip(a, b)) / (na * nb)


def main() -> None:
    s = get_settings()
    print(f"embedding_provider={s.embedding_provider!r}  model={s.embedding_model!r}")
    print(f"current floor={s.semantic_near_duplicate_threshold}  "
          f"current bar={s.semantic_cross_category_threshold}\n")
    llm = get_llm()
    texts = sorted({t for a, b, _ in PAIRS for t in (a, b)})
    vectors = dict(zip(texts, llm.embed(texts, kind="query")))

    para_scores, highest_dist = [], 0.0
    for a, b, is_para in PAIRS:
        c = _cos(vectors[a], vectors[b])
        kind = "PARAPHRASE" if is_para else "DISTINCT  "
        print(f"{kind}  cosine={c:.4f}  {a!r} vs {b!r}")
        if is_para:
            para_scores.append(c)
        else:
            highest_dist = max(highest_dist, c)

    # Hard constraint first (never merge distinct), best-effort second (catch restatements).
    # 0.01 margin absorbs run-to-run float noise without giving away much catch range.
    bar = min(0.999, highest_dist + 0.01)
    caught = sum(1 for c in para_scores if c >= bar)
    print(f"\nhighest distinct = {highest_dist:.4f}  ->  suggested bar = {bar:.3f}")
    print(f"suggested: TSG_SEMANTIC_CROSS_CATEGORY_THRESHOLD={bar:.3f}")
    print(f"at that bar: no known distinct pair merges; {caught}/{len(para_scores)} known "
          f"paraphrase pairs are caught — the rest survive as separate threats (the accepted "
          f"trade-off: distinct threats are never sacrificed to catch more paraphrases)")
    if highest_dist >= 0.995:
        print("WARNING: a distinct pair scores >= 0.995 — this embedder barely separates "
              "anything on labels; the bar collapses to identity-only dedup. Escalate.")
        sys.exit(1)


if __name__ == "__main__":
    main()
