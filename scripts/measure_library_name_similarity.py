"""Where should the "same threat, different words" bar go? Measure, don't guess. READ-ONLY.

promote-to-library dedups on exact spelling only (dal.find_catalogue_id_by_norm_name via
core.naming.normalize_name, a character canonicaliser), so three phrasings of one threat mint three
rows. The fix compares by MEANING instead — which needs a cosine threshold, and a threshold picked
by taste is the weakest part of any such fix.

So: score the pairs we KNOW are duplicates against pairs we know are distinct, and look for a gap.

  * duplicates   — the pairs named in --known / --known-types
  * same-type    — every pair sharing a parent type: the pairs the catalogue-level check must
                   actually separate, since candidates are always type-scoped
  * distinct     — pairs under DIFFERENT types, which the library's own curation says are not the
                   same threat

A usable bar sits in the gap between the duplicate and distinct distributions. If they OVERLAP, say
so and stop: at that point any number is a coin flip, and a wrong merge silently drops a threat from
the risk register where a missed duplicate stays visible.

Uses the same embedding cache the pipeline uses (embeddings.get_vectors, groups
'threat_catalogue' / 'threat_type') and the same passage transform (catalogue_passage_text), so
warm rows cost nothing and the numbers here are the numbers the real check will see.
"""
from __future__ import annotations

import argparse
import itertools
import sys

from sqlalchemy import select

from app.core.config import get_settings
from app.db import models as m
from app.db.engine import db_session
from app.pipeline import embeddings, hybrid_search
from app.pipeline.llm import get_llm

sys.stdout.reconfigure(encoding="utf-8", errors="replace")


def _pct(values: list[float], q: float) -> float:
    if not values:
        return float("nan")
    s = sorted(values)
    return s[min(len(s) - 1, int(q * (len(s) - 1)))]


def _describe(label: str, values: list[float]) -> None:
    if not values:
        print(f"  {label:<26} (none)")
        return
    print(f"  {label:<26} n={len(values):<6} min={min(values):.3f}  p50={_pct(values, .5):.3f}  "
        f"p95={_pct(values, .95):.3f}  p99={_pct(values, .99):.3f}  max={max(values):.3f}")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--known", default="647,648,649",
                    help="comma-separated ThreatCatalogueIDs known to be the SAME threat")
    ap.add_argument("--known-types", default="28,164",
                    help="comma-separated ThreatTypeIDs known to be the SAME type")
    ap.add_argument("--max-distinct", type=int, default=4000,
                    help="cap on cross-type pairs sampled for the distinct distribution")
    ap.add_argument("--rerank", action="store_true",
                    help="also score the high-cosine same-type pairs through the reranker — the "
                        "only mechanism that reads both names together, so the only one that "
                        "can tell an opposite ('Direct'/'Indirect') from a synonym")
    args = ap.parse_args()

    s = get_settings()
    llm = get_llm()
    known = [int(x) for x in args.known.split(",") if x.strip()]
    known_types = [int(x) for x in args.known_types.split(",") if x.strip()]

    with db_session() as sess:
        cat = [dict(r) for r in sess.execute(
            select(m.Threat_Catalogue.ThreatCatalogueID, m.Threat_Catalogue.ThreatName,
                m.Threat_Catalogue.ThreatTypeID, m.Threat_Catalogue.IsActive)
            .where(m.Threat_Catalogue.IsDeleted == False)).mappings()]
        typ = [dict(r) for r in sess.execute(
            select(m.Threat_Type.ThreatTypeID, m.Threat_Type.ThreatTypeName,
                m.Threat_Type.IsActive)
            .where(m.Threat_Type.IsDeleted == False)).mappings()]

    print(f"library: {len(typ)} types, {len(cat)} threats")

    # The same transform the pipeline warms with, so cached rows cost nothing and the score here
    # is the score the real check will compute.
    limit = s.max_embed_chars
    cat_text = {r["ThreatCatalogueID"]: embeddings.catalogue_passage_text(r["ThreatName"], limit)
                for r in cat}
    typ_text = {r["ThreatTypeID"]: str(r["ThreatTypeName"] or "").strip()[:limit] for r in typ}

    print("embedding (cached rows are free; pending rows are computed now)...")
    cvecs = embeddings.get_vectors(llm, sorted(set(cat_text.values())),
                                model_id=s.embedding_model, group="threat_catalogue",
                                kind="passage", compute=True)
    tvecs = embeddings.get_vectors(llm, sorted(set(typ_text.values())),
                                model_id=s.embedding_model, group="threat_type",
                                kind="passage", compute=True)

    def csim(a: int, b: int) -> float | None:
        va, vb = cvecs.get(cat_text[a]), cvecs.get(cat_text[b])
        return None if va is None or vb is None else hybrid_search.cosine(va, vb)

    def tsim(a: int, b: int) -> float | None:
        va, vb = tvecs.get(typ_text[a]), tvecs.get(typ_text[b])
        return None if va is None or vb is None else hybrid_search.cosine(va, vb)

    by_id = {r["ThreatCatalogueID"]: r for r in cat}
    tname = {r["ThreatTypeID"]: r["ThreatTypeName"] for r in typ}

    print("\n=== KNOWN DUPLICATES (the pairs the fix must catch) ===")
    known_scores: list[float] = []
    for a, b in itertools.combinations([k for k in known if k in by_id], 2):
        v = csim(a, b)
        if v is None:
            continue
        known_scores.append(v)
        print(f"  {v:.3f}  {a}: {by_id[a]['ThreatName'][:52]}")
        print(f"         {b}: {by_id[b]['ThreatName'][:52]}")
    known_type_scores: list[float] = []
    for a, b in itertools.combinations([k for k in known_types if k in tname], 2):
        v = tsim(a, b)
        if v is None:
            continue
        known_type_scores.append(v)
        print(f"  {v:.3f}  TYPE {a}: {tname[a][:36]}  <->  {b}: {tname[b][:36]}")

    print("\n=== DISTRIBUTIONS ===")
    same_type = [v for a, b in itertools.combinations(cat, 2)
                if a["ThreatTypeID"] == b["ThreatTypeID"]
                and (v := csim(a["ThreatCatalogueID"], b["ThreatCatalogueID"])) is not None]
    cross: list[float] = []
    for a, b in itertools.combinations(cat, 2):
        if a["ThreatTypeID"] == b["ThreatTypeID"]:
            continue
        v = csim(a["ThreatCatalogueID"], b["ThreatCatalogueID"])
        if v is not None:
            cross.append(v)
        if len(cross) >= args.max_distinct:
            break
    type_pairs = [v for a, b in itertools.combinations(typ, 2)
                if (v := tsim(a["ThreatTypeID"], b["ThreatTypeID"])) is not None]

    _describe("known duplicates", known_scores + known_type_scores)
    _describe("same-type threat pairs", same_type)
    _describe("cross-type threat pairs", cross)
    _describe("type-vs-type pairs", type_pairs)

    # THE pool that decides the catalogue bar. get_possible_names scopes candidates to one type
    # (grounding.py:150), so the catalogue check only ever compares rows that share a parent —
    # cross-type pairs are never candidates for each other and must not set the bar. Printed with
    # names because this pool is CONTAMINATED: the library's existing duplicates live in here, so
    # a high score is only evidence against the bar if the pair is genuinely distinct.
    print("\n=== TOP SAME-TYPE PAIRS (the pool the catalogue bar must survive) ===")
    top_same = sorted(((v, a, b) for a, b in itertools.combinations(cat, 2)
                    if a["ThreatTypeID"] == b["ThreatTypeID"]
                    and (v := csim(a["ThreatCatalogueID"], b["ThreatCatalogueID"])) is not None),
                    key=lambda r: -r[0])[:15]
    for v, a, b in top_same:
        print(f"  {v:.3f}  type {a['ThreatTypeID']:<4} {a['ThreatName'][:46]}")
        print(f"                  {b['ThreatName'][:46]}")

    print("\n=== TOP CROSS-TYPE PAIRS (never compared by the catalogue check; "
        "relevant only to the TYPE bar) ===")
    top = sorted(((v, a, b) for a, b in itertools.combinations(cat, 2)
                if a["ThreatTypeID"] != b["ThreatTypeID"]
                and (v := csim(a["ThreatCatalogueID"], b["ThreatCatalogueID"])) is not None),
                reverse=True)[:5]
    for v, a, b in top:
        print(f"  {v:.3f}  {a['ThreatName'][:44]}  <->  {b['ThreatName'][:44]}")

    if args.rerank:
        # Cosine compares two independently-made summaries, which is why it rates "Direct" and
        # "Indirect" as near-identical. A reranker reads both strings TOGETHER, so it is the only
        # mechanism in this codebase that could tell an opposite from a synonym. Scored on the
        # high-cosine same-type pairs ONLY — those are the pairs a cosine bar would wrongly merge,
        # so they are the ones that decide whether a rerank bar is safe. Rerank scale is 0-100,
        # the same scale as grounding_match_threshold.
        print("\n=== RERANK ON THE PAIRS COSINE CANNOT SEPARATE ===")
        probe = list(top_same[:20])
        for x, y in itertools.combinations([k for k in known if k in by_id], 2):
            v = csim(x, y)
            if v is not None:
                probe.append((v, by_id[x], by_id[y]))
        for v, a, b in sorted(probe, key=lambda r: -r[0]):
            try:
                score = llm.rerank(a["ThreatName"], [b["ThreatName"]])[0]
            except Exception as exc:  # noqa: BLE001 - a measurement script reports, never raises
                print(f"  rerank failed: {exc}")
                break
            dup = "DUP " if a["ThreatCatalogueID"] in known and b["ThreatCatalogueID"] in known \
                else "    "
            print(f"  cos={v:.3f}  rerank={score:8.3f}  {dup}{a['ThreatName'][:40]}")
            print(f"                                 {b['ThreatName'][:40]}")

        # The TYPE half matters more than the catalogue half: a twin type orphans every threat
        # curated under the original (get_possible_names scopes candidates to one type), so the
        # bar has to hold here too.
        print("\n=== RERANK, TYPE LEVEL ===")
        tprobe = sorted(((v, a, b) for a, b in itertools.combinations(typ, 2)
                        if (v := tsim(a["ThreatTypeID"], b["ThreatTypeID"])) is not None),
                        key=lambda r: -r[0])[:12]
        for x, y in itertools.combinations([k for k in known_types if k in tname], 2):
            v = tsim(x, y)
            if v is not None:
                tprobe.append((v, {"ThreatTypeID": x, "ThreatTypeName": tname[x]},
                            {"ThreatTypeID": y, "ThreatTypeName": tname[y]}))
        for v, a, b in sorted(tprobe, key=lambda r: -r[0]):
            try:
                score = llm.rerank(a["ThreatTypeName"], [b["ThreatTypeName"]])[0]
            except Exception as exc:  # noqa: BLE001 - a measurement script reports, never raises
                print(f"  rerank failed: {exc}")
                break
            dup = "DUP " if a["ThreatTypeID"] in known_types and b["ThreatTypeID"] in known_types \
                else "    "
            print(f"  cos={v:.3f}  rerank={score:8.3f}  {dup}{a['ThreatTypeName'][:34]}"
                f"  <->  {b['ThreatTypeName'][:34]}")

    print("\n=== THE GAP ===")
    all_known = known_scores + known_type_scores
    if not all_known:
        print("  no known-duplicate pairs scored — pass --known/--known-types ids that exist")
        return 1
    floor = min(all_known)
    # The bar must sit BELOW every known duplicate (or it catches none) and ABOVE almost every
    # pair the check will actually SEE. That pool is same-type, not cross-type: the catalogue
    # check is type-scoped, so cross-type pairs are never candidates and would flatter the bar.
    # p99 rather than max, so one outlier pair cannot set the bar for the whole library.
    ceiling = _pct(same_type, 0.99)
    print(f"  lowest known duplicate : {floor:.3f}   <- the bar must be at or below this")
    print(f"  p99 of distinct pairs  : {ceiling:.3f}   <- the bar must be above this")
    if floor > ceiling:
        print(f"\n  SEPARATED. Any bar in ({ceiling:.3f}, {floor:.3f}] works; "
            f"midpoint {(floor + ceiling) / 2:.3f}.")
        print("  Prefer the HIGH end of that band: a missed duplicate is visible and fixable, a "
            "wrong merge silently drops a threat from the register.")
        return 0
    print("\n  OVERLAP — the known duplicates are NOT separable from unrelated pairs by cosine on "
        "names alone with this embedding model.")
    print("  Do not pick a number here. Options: add the reranker (a second call, better "
        "precision), compare richer text than the bare name, or keep the check advisory (flag "
        "for a curator) rather than automatic.")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
