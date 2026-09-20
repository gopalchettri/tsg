"""Does the library already hold this threat under a different wording?

promote-to-library dedups on exact spelling only (dal.find_catalogue_id_by_norm_name, over
core.naming.normalize_name — a CHARACTER canonicaliser: case, accents, punctuation). So three
phrasings of one threat mint three rows, and because minted rows are born pending while grounding
filters IsActive==True, session 2 cannot see session 1's row and mints another. That ratchet put
three wordings of one threat in the live library.

Grounding DID find the match at generation time and scored it, then discarded it
(grounding.py:1445 collapses a below-threshold row to None). With no column to carry that forward,
the question has to be asked again here — but against a pool grounding cannot use: live rows
INCLUDING pending ones, the same IsDeleted-only rule find_catalogue_id_by_norm_name already
applies. That difference is the whole point; the pending twin is exactly what grounding was blind
to.

WHY THE RERANKER AND NOT COSINE. Measured on the real library
(scripts/measure_library_name_similarity.py): cosine over these names does not separate. Genuinely
opposite threats score ABOVE the known duplicates — "White-Box Optimization" vs "Black-Box
Optimization" at 0.972, "Direct" vs "Indirect" at 0.966, against known duplicates bottoming out at
0.953. Threat names are short and structurally alike, so two independently-made embeddings cannot
tell an opposite from a synonym. The reranker reads both names TOGETHER and separates cleanly:
those same opposites score 0.6 / 6.8, while the real duplicates score 84.2 - 99.996. That is the
gap the bar sits in.

THREATS ONLY, NEVER TYPES. The same measurement over Threat_Type names shows no separation at all:
"Obtain Capabilities" vs "Develop Capabilities" reranks 99.8 while a real type duplicate reranks
20.9. Type names are two or three words — not enough text for any mechanism to judge — so promoting
a novel TYPE still mints, exactly as before. Do not extend this module to types without re-running
that measurement.

NO SESSION IS HELD DURING THE MODEL CALL. Split in two on purpose: `probe` does the DB reads,
`pick` does the scoring. The caller closes its read session between them, so a remote reranker
(reranker_provider='litellm_proxy' takes an _llm_slot with the 90s call budget) can never block
while this process holds a database transaction — least of all promote's write transaction.
"""
from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.core.logging import get_logger
from app.db import models as m
from app.db.dal import find_type_id_by_norm_name as dal_find_type
from app.pipeline import grounding
from app.pipeline.llm import LLMClient

# Straight from pipeline_common, not via app.pipeline.tasks (promote's spelling) — tasks pulls in
# the whole Celery-side pipeline, and this module is imported by an API route.
from app.pipeline.pipeline_common import asset_agnostic_name

log = get_logger(__name__)

#: Sanity bound on a name sent to the reranker; Threat_Catalogue.ThreatName is Unicode(500).
_MAX_NAME = 500

#: How many near-duplicate pairs an import report carries. Matches library_import's own
#: RESULT_LIST_CAP convention: a job result is a summary a human reads, not a dataset.
_REPORT_CAP = 50


@dataclass(frozen=True)
class ReuseProbe:
    """Everything the scoring step needs, read from the database in one go."""
    generic_name: str
    type_id: int
    candidates: tuple[tuple[int, str], ...]
    threshold: float


def probe(sess: Session, threat: Any, *, asset_name: str | None,
        llm: LLMClient, settings: Settings) -> ReuseProbe | None:
    """DB reads only — no model call, so this is safe inside any session. None = nothing to score.

    Candidates are IsDeleted-only, matching dal.find_catalogue_id_by_norm_name: a PENDING row
    counts as "the library already has this", which is precisely the row grounding could not see.

    Returns None when reuse cannot apply at all:
      * the threat already carries a catalogue id — promote's own stored-id branch handles it;
      * the threat carries no type id — promotion is about to MINT a type, so there is no existing
        family to search and nothing to reuse (types are deliberately out of scope, see module doc);
      * the family is empty.
    """
    if threat.ThreatCatalogueID is not None or threat.ThreatTypeID is None:
        return None

    generic = threat.GenericName or asset_agnostic_name(threat.ThreatName, asset_name or "")
    generic = (generic or threat.ThreatName or "")[:_MAX_NAME]
    if not generic.strip():
        return None

    rows = sess.execute(
        select(m.Threat_Catalogue.ThreatCatalogueID, m.Threat_Catalogue.ThreatName)
        .where(m.Threat_Catalogue.ThreatTypeID == threat.ThreatTypeID,
            m.Threat_Catalogue.IsDeleted == False)
        .order_by(m.Threat_Catalogue.ThreatCatalogueID)).all()
    candidates = tuple((r[0], str(r[1] or "")[:_MAX_NAME]) for r in rows if (r[1] or "").strip())
    if not candidates:
        return None

    # The SAME bar grounding uses to say "this proposal IS this library row" — the identical
    # question on the identical 0-100 rerank scale, so a second setting would be a second thing to
    # keep in step. It is calibrated per embedding+reranker pair and fails safe both ways: drift it
    # up and a duplicate is missed (visible, fixable); drift it down and the measured distinct
    # pairs, which top out at 23, still do not merge.
    threshold = grounding.resolve_thresholds(sess, llm, settings).value
    return ReuseProbe(generic_name=generic, type_id=threat.ThreatTypeID,
                    candidates=candidates, threshold=threshold)


def pick(probe_: ReuseProbe | None, llm: LLMClient) -> tuple[int, float] | None:
    """Score the probe and return (catalogue_id, score), or None to mint. NO database access.

    Fails OPEN — a reranker that is down, slot-starved or misbehaving returns None, so promotion
    mints exactly as it does today rather than 5xx-ing a curator's click. Logged at ERROR, not
    warning: an unnoticed fail-open here is how the library filled with twins in the first place.
    """
    if probe_ is None:
        return None
    names = [name for _, name in probe_.candidates]
    try:
        scores = llm.rerank(probe_.generic_name, names)
    except Exception:
        log.exception("library_match.rerank_failed", type_id=probe_.type_id,
                    candidates=len(names))
        return None
    if len(scores) != len(names):
        # Same contract as grounding.find_closest_match's length guard: mispaired scores would
        # attach one threat's verdict to another's row, which HERE means merging the wrong two
        # threats — silently, and with no reviewer in the loop.
        log.error("library_match.rerank_length_mismatch", got=len(scores), want=len(names))
        return None

    best_i = max(range(len(scores)), key=lambda i: scores[i])
    best = scores[best_i]
    if best < probe_.threshold:
        return None
    cid, name = probe_.candidates[best_i]
    log.info("library_match.reuse", catalogue_id=cid, score=round(best, 2),
            threshold=probe_.threshold, proposed=probe_.generic_name, matched=name)
    return cid, best


def near_duplicates(sess: Session, llm: LLMClient, settings: Settings,
                    incoming: Sequence[tuple[str, str]], *, limit: int = 300) -> dict[str, Any]:
    """Which rows a bulk import would ADD that already resemble something in the library?

    REPORTS, never merges — the deliberate difference from promote. Imported rows carry external
    standard identifiers (AML.T0043.000, INP36, AC19), and collapsing two of those would corrupt
    the mapping back to the source standard, which is worse than the duplicate it avoids. They are
    also curator-vouched and born active, so the invisibility ratchet that justifies automatic
    linking on the promote path does not apply here. A curator triggering an import — with
    `dry_run` available — is exactly the human this report is for.

    `incoming` is (type_name, threat_name) pairs. Scored per type, because the library's own
    candidate pool is type-scoped; a name is only compared against the family it would join.
    Matching the type by normalized name mirrors what the importer itself does, so a type the
    import is about to MINT simply has no family and nothing to report.

    Bounded, and says so: `limit` caps how many names are scored and `skipped_for_cap` reports
    what was not, because a silent cap reads as "nothing found".
    """
    by_type: dict[str, list[str]] = {}
    for type_name, threat_name in incoming:
        if (threat_name or "").strip():
            by_type.setdefault(type_name, []).append(threat_name[:_MAX_NAME])

    threshold = grounding.resolve_thresholds(sess, llm, settings).value
    queries: list[tuple[str, Sequence[str]]] = []
    context: list[tuple[str, list[tuple[int, str]]]] = []
    scored = 0
    skipped = 0
    for type_name, names in by_type.items():
        type_id = dal_find_type(sess, type_name)
        if type_id is None:
            continue  # the import is about to mint this type: no family, nothing to compare
        rows = sess.execute(
            select(m.Threat_Catalogue.ThreatCatalogueID, m.Threat_Catalogue.ThreatName)
            .where(m.Threat_Catalogue.ThreatTypeID == type_id,
                m.Threat_Catalogue.IsDeleted == False)
            .order_by(m.Threat_Catalogue.ThreatCatalogueID)).all()
        family = [(r[0], str(r[1] or "")[:_MAX_NAME]) for r in rows if (r[1] or "").strip()]
        if not family:
            continue
        for name in names:
            if scored >= limit:
                skipped += 1
                continue
            scored += 1
            queries.append((name, [n for _, n in family]))
            context.append((name, family))

    pairs: list[dict[str, Any]] = []
    if queries:
        try:
            batched = llm.rerank_many(queries)
        except Exception:
            log.exception("library_match.import_scan_failed", queries=len(queries))
            return {"scored": 0, "skipped_for_cap": skipped, "pairs": [],
                    "error": "similarity scan unavailable — the import itself was unaffected"}
        for (name, family), scores in zip(context, batched, strict=True):
            if not scores or len(scores) != len(family):
                continue  # rerank_many reports a per-item failure as None; skip, never guess
            best_i = max(range(len(scores)), key=lambda i: scores[i])
            if scores[best_i] < threshold:
                continue
            cid, existing = family[best_i]
            pairs.append({"incoming": name, "catalogue_id": cid, "existing": existing,
                        "score": round(scores[best_i], 2)})

    if pairs:
        log.warning("library_match.import_near_duplicates", count=len(pairs), scored=scored,
                    threshold=threshold)
    return {"scored": scored, "skipped_for_cap": skipped, "pairs": pairs[:_REPORT_CAP]}
