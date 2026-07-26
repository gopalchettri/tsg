#!/usr/bin/env python
"""Calibrate the grounding thresholds against the CURRENTLY CONFIGURED embedding + reranker models.

WHY THIS EXISTS: `TSG_GROUNDING_GROUNDED_THRESHOLD` / `TSG_GROUNDING_CONFIRM_THRESHOLD` /
`SEMANTIC_MATCH_THRESHOLD` are MODEL-SPECIFIC. They were tuned against one embedding+reranker
pair; a different pair (e.g. dev's multilingual-e5-large @1024 vs UAT's qwen3-embedding-8b @4096)
produces a different similarity distribution for the SAME threat/library pair. Nothing in the app
detects that — a threat that grounds cleanly in dev can come back `flagged` in UAT, silently, with
no error anywhere. Since only `flagged` threats are eligible for library promotion on accept, and
`grounded` ones skip human confirmation, mis-set thresholds quietly change business behaviour.

So: don't eyeball the numbers, generate them. Run this against a labelled sample whenever the
embedding or reranker model changes, and move the thresholds to what it reports.

    python scripts/calibrate_grounding.py labelled_pairs.csv
    python scripts/calibrate_grounding.py labelled_pairs.csv --sector-ids 1,4

Input CSV — one row per threat you already know the right answer for:

    category,type,name,expected
    Tampering,Firmware Tampering,Bootloader implant,grounded
    Spoofing,Credential Replay,Totally novel made-up threat,flagged

`expected` is one of: grounded | confirm | flagged.
Aim for ~30+ rows with a realistic mix; too few and the suggested cutoffs mean nothing.

Runs against the REAL configured models and the REAL threat library (nothing stubbed), so point
it at the environment you are calibrating — it reads the same .env every worker reads.

Exit codes: 0 = current thresholds classify every row correctly · 1 = misclassifications, see the
report · 2 = bad input/config.
"""
from __future__ import annotations

import argparse
import csv
import os
import statistics
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))  # make `app` importable

from app.core.config import get_settings  # noqa: E402
from app.core.logging import configure_logging  # noqa: E402
from app.db.engine import db_session  # noqa: E402
from app.pipeline import grounding  # noqa: E402
from app.pipeline.llm import get_llm  # noqa: E402

_VALID = {"grounded", "confirm", "flagged"}
_BAD_INPUT = 2  # distinct from 1 ("ran fine, thresholds misclassify") so a deploy gate can tell
                # "this tool could not run" apart from "your thresholds need retuning"


def _die(msg: str) -> None:
    print(msg, file=sys.stderr)
    raise SystemExit(_BAD_INPUT)


def _load(path: str) -> list[dict[str, str]]:
    try:
        # utf-8-SIG: Excel writes a BOM, which would otherwise ride on the first header name and
        # produce a bogus "missing column(s) ['category']" for a perfectly valid file.
        with open(path, newline="", encoding="utf-8-sig") as fh:
            rows = [{(k or "").strip().lower(): (v or "").strip() for k, v in r.items()}
                    for r in csv.DictReader(fh)]
    except OSError as exc:
        _die(f"{path}: {exc}")
    rows = [r for r in rows if any(r.values())]  # tolerate trailing blank lines
    if not rows:
        _die(f"{path}: no rows")
    missing = {"category", "type", "name", "expected"} - set(rows[0])
    if missing:
        _die(f"{path}: missing column(s) {sorted(missing)}")
    bad = {r["expected"].lower() for r in rows} - _VALID
    if bad:
        _die(f"{path}: invalid `expected` value(s) {sorted(bad)} — use {sorted(_VALID)}")
    return rows


# ONE definition of "the cutoff between two score classes", shared with the app's own
# auto-calibration (grounding.resolve_thresholds) — this script is the labelled-CSV audit/
# override tool on top of it. Midpoint-between-adjacent-classes cannot emit the inverted
# CONFIRM >= GROUNDED pair that independent per-class margins could (config rejects that pair
# at startup). NOTE on precedence: the app auto-calibrates whenever the thresholds are UNSET in
# env; the numbers this script suggests only take effect if you SET them, which pins both and
# disables auto-calibration.
from app.pipeline.grounding import boundary_between as _boundary  # noqa: E402


def _score_all(rows: list[dict[str, str]], sector_ids: list[int]) -> list[tuple[str, float, str]]:
    """(expected, score, actual_status) for every row, through the real grounding path."""
    llm = get_llm()
    out: list[tuple[str, float, str]] = []
    with db_session() as sess:
        cache: dict = {}
        grounding.prime_query_embeddings(llm, [{"type": r["type"], "name": r["name"]} for r in rows], cache)
        for r in rows:
            gr = grounding.find_threat_in_library(
                sess, llm,
                {"category": r["category"], "type": r["type"], "name": r["name"], "actors": []},
                sector_ids=sector_ids, cache=cache)
            out.append((r["expected"].lower(), float(gr.score), str(gr.status)))
    return out


def _band(scores: list[float]) -> str:
    if not scores:
        return "        (none)"
    return (f"        n={len(scores):<4} min={min(scores):6.1f}  median={statistics.median(scores):6.1f}  "
            f"max={max(scores):6.1f}")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("csv_path")
    ap.add_argument("--sector-ids", default="", help="comma-separated sector ids to scope the library by")
    args = ap.parse_args()

    configure_logging()
    s = get_settings()
    rows = _load(args.csv_path)
    sector_ids = [int(x) for x in args.sector_ids.split(",") if x.strip()]

    print(f"\nembedding: {s.embedding_model} ({s.embedding_provider}, dim={s.embedding_dimensions})")
    print(f"reranker : {s.reranker_model} ({s.reranker_provider})")
    print(f"current  : grounded>={s.grounding_grounded_threshold}  confirm>={s.grounding_confirm_threshold}  "
        f"semantic_match>={s.semantic_match_threshold}\n")

    results = _score_all(rows, sector_ids)
    by_expected: dict[str, list[float]] = {}
    for expected, score, _actual in results:
        by_expected.setdefault(expected, []).append(score)

    print("observed score distribution, by the label YOU gave the row:")
    for label in ("grounded", "confirm", "flagged"):
        print(f"    {label}:")
        print(_band(by_expected.get(label, [])))

    grounded = by_expected.get("grounded", [])
    confirm = by_expected.get("confirm", [])
    flagged = by_expected.get("flagged", [])

    # Each cutoff separates ADJACENT classes, so `confirm` rows constrain BOTH — leaving them out
    # (they were only printed before) let the tool recommend thresholds that misclassify rows in
    # its own input without ever saying so.
    grounded_th = _boundary(confirm + flagged, grounded)   # everything below `grounded` vs grounded
    confirm_th = _boundary(flagged, confirm + grounded)    # flagged vs everything at/above confirm

    # The TSG_ prefix is REQUIRED and was missing here: unlike ~10 other settings, these two
    # fields carry no AliasChoices, so Settings only ever binds the prefixed form (env_prefix in
    # config.py). Printing the bare names sent operators to a .env line that is silently ignored
    # — they would restart, stay on the 75/60 defaults, and see no error anywhere.
    print("\nsuggested thresholds (the TSG_ prefix is required — a bare name is ignored):")
    if grounded_th is not None:
        print(f"    TSG_GROUNDING_GROUNDED_THRESHOLD={grounded_th:.0f}")
    if confirm_th is not None:
        print(f"    TSG_GROUNDING_CONFIRM_THRESHOLD={confirm_th:.0f}")
    if grounded_th is None and grounded and (confirm or flagged):
        print(f"    !! OVERLAP at the grounded boundary: a 'grounded' row scored {min(grounded):.1f}, "
            f"but a lower-class row scored {max(confirm + flagged):.1f}.")
    if confirm_th is None and flagged and (confirm or grounded):
        print(f"    !! OVERLAP at the confirm boundary: a 'flagged' row scored {max(flagged):.1f}, "
            f"but a higher-class row scored {min(confirm + grounded):.1f}.")
    if grounded_th is None or confirm_th is None:
        if not (grounded and flagged):
            print("    (need rows labelled BOTH 'grounded' and 'flagged' to bound both ends)")
        else:
            print("       No threshold separates those classes — this model pair cannot tell them apart.\n"
                "       Re-check the labels first; if they are right, the model pair is unfit for this\n"
                "       library and no tuning will fix it.")

    wrong = [(e, sc, a) for e, sc, a in results if e != a]
    print(f"\nunder the CURRENT thresholds: {len(results) - len(wrong)}/{len(results)} classified as labelled")
    for expected, score, actual in wrong:
        print(f"    expected {expected:<9} got {actual:<9} score={score:6.1f}")
    return 1 if wrong else 0


def _self_check() -> None:
    """`python scripts/calibrate_grounding.py --self-check` — no DB, no models, no CSV.

    The one thing worth proving without infrastructure: the suggested pair can never come back
    inverted. config.py rejects CONFIRM >= GROUNDED at startup, so emitting such a pair would be
    advice that cannot boot — and the earlier independent-margin arithmetic did exactly that
    whenever the classes sat close together."""
    # tight but separable: confirm sits between flagged and grounded, gaps of 1
    g, c, f = _boundary([50.0, 60.0], [61.0]), _boundary([50.0], [60.0, 61.0]), None
    assert g is not None and c is not None and c < g, (c, g)
    # adjacent classes overlapping → no cutoff, never a fabricated one
    assert _boundary([70.0], [65.0]) is None
    assert _boundary([70.0], [70.0]) is None  # equal is still unseparable
    assert _boundary([], [10.0]) is None and _boundary([10.0], []) is None
    # midpoint lands strictly inside the gap
    assert _boundary([40.0], [60.0]) == 50
    print("calibrate_grounding self-check: OK", f)


if __name__ == "__main__":
    if "--self-check" in sys.argv:
        _self_check()
        sys.exit(0)
    sys.exit(main())
