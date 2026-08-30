#!/usr/bin/env python
"""Calibrate the grounding threshold against the CURRENTLY CONFIGURED embedding + reranker models.

WHY THIS EXISTS: `TSG_GROUNDING_MATCH_THRESHOLD` / `SEMANTIC_MATCH_THRESHOLD` are
MODEL-SPECIFIC. They were tuned against one embedding+reranker pair; a different pair (e.g. dev's
multilingual-e5-large @1024 vs UAT's qwen3-embedding-8b @4096) produces a different similarity
distribution for the SAME threat/library pair. Nothing in the app detects that — a threat that
matches cleanly in dev can come back `unverified` in UAT, silently, with no error anywhere. Since
`unverified` threats are the ones eligible for library promotion on accept, a mis-set threshold
quietly changes business behaviour.

So: don't eyeball the number, generate it. Run this against a labelled sample whenever the
embedding or reranker model changes, and move the threshold to what it reports.

    python scripts/calibrate_grounding.py labelled_pairs.csv
    python scripts/calibrate_grounding.py labelled_pairs.csv

There are THREE ways to set this threshold, in descending order of trust:

    1. this script with a labelled CSV  — ground truth, best answer, needs curator effort
    2. an unlabelled calibration sweep  — auto-labelled from the library itself, no effort:
        POST /v1/tsg/grounding/calibrate          (on a deployment with a running worker)
        python scripts/calibrate_grounding.py --recalibrate    (offline, in this process)
       Worker boot queues (2) automatically when the current model pair has no stored value.
    3. TSG_GROUNDING_MATCH_THRESHOLD in env    — a hand-pinned number; DISABLES 1 and 2 entirely

(2) stores per (embedding_model, reranker_model) in Mongo, so it is measured once and reused by
every worker and every later boot. (1) prints a number for you to pin, which means opting into
(3) — so only do it when your labels really are better than the library's own signal.

Input CSV — one row per threat you already know the right answer for:

    category,type,name,expected
    Tampering,Firmware Tampering,Bootloader implant,verified
    Spoofing,Credential Replay,Totally novel made-up threat,unverified

`expected` is one of: verified | unverified.
Aim for ~30+ rows with a realistic mix; too few and the suggested cutoffs mean nothing.

Runs against the REAL configured models and the REAL threat library (nothing stubbed), so point
it at the environment you are calibrating — it reads the same .env every worker reads.

Exit codes: 0 = the current threshold classifies every row correctly · 1 = misclassifications, see
the report · 2 = bad input/config.
"""
from __future__ import annotations

import argparse
import csv
import os
import statistics
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))  # make `app` importable

from app.core.config import get_settings
from app.core.logging import configure_logging
from app.db.engine import db_session
from app.pipeline import grounding
from app.pipeline.llm import get_llm

_VALID = {"verified", "unverified"}
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
# calibration sweep (grounding.calibrate) — this script is the labelled-CSV audit/override tool
# on top of it. Sharing it matters: if this script scored its labelled rows by a different rule
# than the app uses on the library, its "suggested threshold" would be advice about a cutoff the
# app never applies.
# It takes the BEST SPLIT, not a perfect gap — so it emits a number even when the classes
# overlap, and _quality (Youden's J) is what says which of the two you got. On cleanly separable
# classes it still returns the gap's midpoint, which can never land on a measured score.
# NOTE on precedence: the app calibrates whenever the threshold is UNSET in env; the number this
# script suggests only takes effect if you SET it, which DISABLES calibration from then on.
from app.pipeline.grounding import boundary_between as _boundary
from app.pipeline.grounding import separation_quality as _quality


def _score_all(rows: list[dict[str, str]]) -> list[tuple[str, float, str]]:
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
                cache=cache)
            out.append((r["expected"].lower(), float(gr.score), str(gr.status)))
    return out


def _band(scores: list[float]) -> str:
    if not scores:
        return "        (none)"
    return (f"        n={len(scores):<4} min={min(scores):6.1f}  median={statistics.median(scores):6.1f}  "
            f"max={max(scores):6.1f}")


def _recalibrate(force: bool) -> int:
    """`--recalibrate`: run the app's OWN unlabelled calibration here and now, and store the
    result — the same sweep app/pipeline/celery_app.py::calibrate_grounding_task runs, minus the
    broker. For when you want a measured threshold but have no labelled CSV.

    Runs IN THIS PROCESS, so it needs the local models loaded and takes minutes. Prefer
    POST /v1/tsg/grounding/calibrate on a deployment that has a worker; this is the offline
    equivalent for a box with no stack running."""
    s = get_settings()
    key = (s.embedding_model, s.reranker_model)
    if "grounding_match_threshold" in s.model_fields_set:
        print(f"TSG_GROUNDING_MATCH_THRESHOLD is pinned to {s.grounding_match_threshold} in env, "
            "which DISABLES calibration.\nComment it out and re-run, or the stored value will "
            "never be consulted.")
        return _BAD_INPUT
    with db_session() as sess:
        existing = grounding.latest_successful_run(sess, key)
    if not force and existing is not None:
        print(f"this model pair already has a calibration ({existing}). "
            "Re-run with --force to measure it again.")
        return 0
    print(f"calibrating {s.embedding_model} + {s.reranker_model} — this takes minutes...")

    def _tick(phase: str, done: int, total: int) -> None:
        if total and (done == total or done % max(1, total // 20) == 0):
            print(f"    {phase}: {done}/{total}", flush=True)

    # Same ledger the API path writes, so an offline run shows up in GET /calibrations exactly
    # like an operator-triggered one. `started_by` names the tool because there is no HTTP caller
    # to attribute it to — an honest marker beats a blank or a guessed username.
    run_id = grounding.record_calibration_started(
        key, job_id=None, started_by="scripts/calibrate_grounding.py --recalibrate",
        started_by_client=None, forced=force)
    try:
        with db_session() as sess:
            result = grounding.calibrate(sess, get_llm(), s, progress=_tick)
    except BaseException as exc:
        # Close the row before propagating: an abandoned `running` row blocks the next
        # calibration behind the unique index until the stale window expires.
        grounding.record_calibration_finished(run_id, error=repr(exc))
        raise
    grounding.record_calibration_finished(run_id, result=result)

    if result.near_duplicates:
        print(f"\n{len(result.near_duplicates)} near-duplicate library pair(s) — each is scored as "
            "an impostor against its own twin and drags the cutoff down. Dedupe and re-run:")
        for pair in result.near_duplicates[:10]:
            print(f"    {pair}")
    if result.match_th is None:
        print("\nNO SIGNAL: no cutoff classified better than chance "
            f"(negatives={result.negatives}, positives={result.positives}).\n"
            f"Recorded as run {run_id} with status 'no_signal' — the sweep is not lost, it simply "
            "found nothing usable. See the log for the full diagnosis.")
        return 1
    print(f"\nstored match_th={result.match_th:.2f} (quality J={result.quality:.3f}, "
        f"negatives={result.negatives}, positives={result.positives}) as run {run_id}.")
    print("Every worker picks this up on its next threshold resolve — no restart needed.")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("csv_path", nargs="?", help="labelled CSV; omit when using --recalibrate")
    ap.add_argument("--recalibrate", action="store_true",
                    help="run the app's own unlabelled calibration now and STORE it (no CSV needed)")
    ap.add_argument("--force", action="store_true",
                    help="with --recalibrate: overwrite an existing stored calibration")
    args = ap.parse_args()

    if args.recalibrate:
        configure_logging()
        return _recalibrate(args.force)
    if not args.csv_path:
        _die("a labelled CSV path is required (or pass --recalibrate to measure without labels)")

    configure_logging()
    s = get_settings()
    rows = _load(args.csv_path)

    print(f"\nembedding: {s.embedding_model} ({s.embedding_provider}, dim={s.embedding_dimensions})")
    print(f"reranker : {s.reranker_model} ({s.reranker_provider})")
    print(f"current  : verified>={s.grounding_match_threshold}  "
        f"semantic_match>={s.semantic_match_threshold}\n")

    results = _score_all(rows)
    by_expected: dict[str, list[float]] = {}
    for expected, score, _actual in results:
        by_expected.setdefault(expected, []).append(score)

    print("observed score distribution, by the label YOU gave the row:")
    for label in ("verified", "unverified"):
        print(f"    {label}:")
        print(_band(by_expected.get(label, [])))

    verified = by_expected.get("verified", [])
    unverified = by_expected.get("unverified", [])

    match_th = _boundary(unverified, verified)   # the best cutoff between the two classes

    # The TSG_ prefix is REQUIRED and was missing here: unlike ~10 other settings, this field
    # carries no AliasChoices, so Settings only ever binds the prefixed form (env_prefix in
    # config.py). Printing the bare name sent operators to a .env line that is silently ignored
    # — they would restart, stay on the default, and see no error anywhere.
    print("\nsuggested threshold (the TSG_ prefix is required — a bare name is ignored):")
    if match_th is not None:
        # Quality, not just the number. boundary_between TOLERATES overlap now (it takes the best
        # split rather than demanding a perfect gap), so "it printed a number" no longer implies
        # the classes were cleanly separable — J is the field that says which of the two it was.
        j = _quality(unverified, verified, match_th)
        print(f"    TSG_GROUNDING_MATCH_THRESHOLD={match_th:.0f}")
        print(f"    separation quality (Youden's J): {j:.3f}  "
            f"({'clean — the classes separate' if j >= 0.99 else 'PARTIAL — the classes overlap'})")
        if j < 0.99:
            miss_v = sum(1 for x in verified if x < match_th)
            miss_u = sum(1 for x in unverified if x >= match_th)
            print(f"    at this cutoff {miss_v}/{len(verified)} 'verified' rows fall below it and "
                f"{miss_u}/{len(unverified)} 'unverified' rows sit at/above it.")
            print("    Re-check those labels first; if they are right, this is the best this model "
                "pair can do on this library.")
    elif not (verified and unverified):
        print("    (need rows labelled BOTH 'verified' and 'unverified' to bound the cutoff)")
    else:
        print(f"    !! NO SIGNAL: no cutoff classified better than chance — a 'verified' row "
            f"scored {min(verified):.1f} and an 'unverified' row scored {max(unverified):.1f}.\n"
            "       Re-check the labels first; if they are right, the model pair is unfit for this\n"
            "       library and no tuning will fix it.")

    wrong = [(e, sc, a) for e, sc, a in results if e != a]
    print(f"\nunder the CURRENT threshold: {len(results) - len(wrong)}/{len(results)} classified as labelled")
    for expected, score, actual in wrong:
        print(f"    expected {expected:<9} got {actual:<9} score={score:6.1f}")
    return 1 if wrong else 0


def _self_check() -> None:
    """`python scripts/calibrate_grounding.py --self-check` — no DB, no models, no CSV.

    Two things are worth proving without infrastructure. First, on cleanly SEPARABLE classes the
    cutoff still lands strictly inside the measured gap — that is the property the emitted number
    depends on, since it is applied as `score >= th` and a cutoff sitting on a measured
    unverified score would band that exact impostor `verified`.

    Second, the OVERLAP cases, which is where the behaviour deliberately changed. boundary_between
    used to demand a perfect gap and returned None on any overlap — on the real library one
    near-synonym pair scoring 99.5 was enough to veto every calibration, forever. It now takes the
    best split instead. But "tolerates overlap" must NOT become "invents a cutoff for noise", so
    the no-signal cases below still have to return None."""
    # SEPARABLE: unchanged from the hard-margin version — strictly inside the gap, at both ends
    th = _boundary([40.0], [60.0])
    assert th == 50.0, th
    assert th is not None and max([40.0]) < th <= min([60.0])
    # a sub-1-point gap must NOT be rounded back onto a measured score (see boundary_between)
    tight = _boundary([71.2], [71.4])
    assert tight is not None and 71.2 < tight <= 71.4, tight
    assert _quality([40.0], [60.0], th) == 1.0  # perfect separation reports as such

    # OVERLAPPING: one impostor above one genuine match no longer vetoes the whole calibration.
    # This is the exact shape measured live (99 impostors low, ONE near-duplicate at 99.5) that
    # made calibration report "impossible" on every single worker boot.
    negs, poss = [60.0, 70.0, 80.0, 99.5], [85.0, 88.0, 90.0, 95.0]
    overlap = _boundary(negs, poss)
    assert overlap is not None, "one outlier must not veto the calibration"
    assert 80.0 < overlap < 85.0, overlap          # the split that misses only the outlier
    assert _quality(negs, poss, overlap) == 0.75   # 4/4 positives kept, 3/4 impostors excluded

    # NO SIGNAL: still None, never a fabricated cutoff
    assert _boundary([70.0], [65.0]) is None       # inverted classes
    assert _boundary([70.0], [70.0]) is None       # identical classes are unseparable
    assert _boundary([], [10.0]) is None and _boundary([10.0], []) is None
    print("calibrate_grounding self-check: OK")


if __name__ == "__main__":
    if "--self-check" in sys.argv:
        _self_check()
        sys.exit(0)
    sys.exit(main())
