"""Stage 1 — library-first threat identification, decomposed.

One sub-pipeline, one module: Top-K retrieval → local rerank relevance gate → pass-1
STRIDE selection → coverage evaluation → bounded LLM gap generation → grounding →
cross-dedup → terminal STRIDE selection → count backfill → persist + audit. Extracted
from tasks.py (structure pass: `find_threats` had grown into a 630-line god function
inside a god file); tasks.py re-exports every externally referenced name, so callers and
tests keep importing via `app.pipeline.tasks` unchanged.

Each stage is a single-responsibility function; `find_threats` is the orchestrator.
Shared mutable round state travels in the `_IdentificationRound` data record — passed explicitly,
never module state. Behavior is bit-for-bit the audited logic; only packaging changed.
"""
from __future__ import annotations

import json
import math
from dataclasses import dataclass, field
from typing import Any, NamedTuple

from sqlalchemy import insert
from sqlalchemy.orm import Session

from app.core import stride, tuning
from app.core.config import get_settings
from app.core.enums import (
    AuditEventType,
    DuplicateReason,
    GroundingStatus,
    SSEEventType,
    StageStatus,
    SubsystemLevel,
    WorkflowStage,
)
from app.core.logging import get_logger
from app.core.tracing import trace_step
from app.db import dal
from app.db import models as m
from app.db.dal import guid
from app.pipeline import coverage, grounding, prompts, threat_retrieval
from app.pipeline.llm import LLMClient, LLMSlotUnavailable, Provenance
from app.pipeline.pipeline_common import (
    _EPOCH,
    ASSET_UNIT_ID,
    _ask_ai,
    _asset_boundary_pattern,
    _safe_text,
    _send_live_update,
    asset_agnostic_name,
    clean_library_name,
    threat_label,
)

log = get_logger(__name__)


# ---------------------------------------------------------------------------------------
# Stage-1-exclusive helpers (moved verbatim from tasks.py)
# ---------------------------------------------------------------------------------------

def _semantic_duplicates(llm: LLMClient, sid: str, ss: int,
                        threats: list[dict],
                        priors: list[dict] | None = None,
                        asset_name: str = "",
                        threshold: float | None = None,
                        compare_within: bool = True) -> dict[str, dict]:
    """Find threats that mean the same thing as another threat, so the caller can drop them.

    Find threat IDs that mean the same thing as a higher-ranked threat already in this
    batch or already active on the session. The caller removes these before inserting.

    Returns {threat_id: {"reason": DuplicateReason, "score": float,
    "duplicate_of_threat_id": str | None}} — the id it matched is only known when the match is a
    THIS-BATCH sibling or a prior threat carrying its own threat_id; still None otherwise (a
    prior entry with no id available), same "best-effort" contract as _duplicate_row's caller.

    Why: exact-match dedup (dal.identity_hash) misses paraphrases — "Data leakage from X"
    and "Unauthorised disclosure of X" would both get inserted as separate threats. This
    catches those by comparing embeddings of the asset-stripped threat label.

    First-wins: each threat is only compared against threats that survived so far, never
    against ones already dropped. Similarity isn't transitive (A~B and B~C doesn't mean
    A~C), so comparing against a dropped item could wrongly chain-drop something. This
    only works because threats always arrive in a stable, deterministic order.

    compare_within=False turns off that within-`threats` comparison entirely (only `priors`
    can drop an entry) — for retrieved LIBRARY candidates, whose distinctness from each
    other the curator already vouched for, so only a match against something OUTSIDE this
    round's library set should count."""
    # Labels are compared with the asset name stripped out first (same as grounding does).
    # Every label ends in "... of <asset name>", so leaving it in mostly just confirms
    # "same asset" rather than "same threat" — stripping it raised the median similarity
    # score from 0.814 to 0.899 in testing.
    #
    # The drop decision is CATEGORY-BLIND. A shared STRIDE category is a ~1-in-6 coincidence
    # that says nothing about two threats meaning the same thing, and an earlier design that
    # judged same-category pairs at a lower bar merged distinct threats that merely share
    # vocabulary (one real asset run collapsed to 6 survivors, all reasoned
    # semantic_same_category). Category affects NEITHER the decision NOR the record now:
    # every semantic drop is written as DuplicateReason.semantic_similarity — the old
    # same/cross-category reasons survive only as historical row values (enums.py).
    def _cat(t: dict) -> str:
        return str(t.get("category") or "").strip().casefold()

    def _key(t: dict) -> str:
        return asset_agnostic_name(threat_label(t), asset_name) or ""

    raw_entries = [(t.get("threat_id"), _key(t), _cat(t)) for t in threats]
    # Separate name for the filtered list so the `if tid and lbl` guard is reflected in the
    # annotation: rebinding the same name keeps the pre-filter `str | None`, and every downstream
    # use (dupes[tid], tid_of[lbl]) then reads as a possible None key.
    entries: list[tuple[str, str, Any]] = [(tid, lbl, c) for tid, lbl, c in raw_entries if tid and lbl]
    prior_entries = [(t.get("threat_id"), _key(t), _cat(t)) for t in (priors or [])]
    prior_entries = [(tid, lbl, c) for tid, lbl, c in prior_entries if lbl]
    if not entries or not (prior_entries or len(entries) > 1):
        return {}
    labels = [lbl for _tid, lbl, _c in entries]
    prior = [lbl for _tid, lbl, _c in prior_entries]
    # The label-clash map resolves to the FIRST holder — the SURVIVOR. On a label clash the
    # survivor is the prior-round threat, or the first of two identical-label proposals; the
    # later holder is the one that gets dropped as its duplicate. Last-writer-wins here
    # corrupted the audit trail: an identical-label duplicate's DuplicateOfThreatID pointed at
    # ITSELF (a threat never inserted) — the map must name the SURVIVING threat's id, not
    # whichever entry happened to write the label last.
    tid_of: dict[str, str] = {}
    for tid, lbl, _c in prior_entries + entries:
        if tid and lbl not in tid_of:
            tid_of[lbl] = tid
    if threshold is None:  # use the caller's session-tuned value if given, otherwise fall back to config
        threshold = get_settings().semantic_near_duplicate_threshold
    # ONE bar for every pair, whatever the categories: real near-duplicates can score LOWER
    # than two genuinely different threats ("Unauthorized disclosure of X" vs "Unauthorized
    # modification of X" measured 0.969 — two REAL threats one word apart), so the bar must sit
    # above that trap for ALL pairs, not just cross-category ones. The session-tuned threshold
    # can only RAISE it (set it to 1.0 to disable the gate without a deploy), never lower it
    # below the config base.
    drop_threshold = max(get_settings().semantic_cross_category_threshold, threshold)
    try:
        # `texts` is just the unique strings to embed, so we don't pay to embed the same
        # label twice. It is NOT a count of how many threats there are — several threats can
        # share one label. (An earlier version bailed out early whenever there were fewer than
        # 2 unique texts, which skipped the exact case it was meant to catch: many threats
        # sharing one label.) The real "nothing to compare" check already happened above;
        # this just guards against an empty list.
        texts = list(dict.fromkeys([lbl for lbl in labels if lbl] + prior))
        if not texts:
            return {}

        vectors = dict(zip(texts, llm.embed(texts, kind="query")))

        norms = {t: math.sqrt(sum(x * x for x in v)) or 1.0 for t, v in vectors.items()}
    except LLMSlotUnavailable:
        # NEVER swallowed — codebase-wide contract (llm.py): the Celery stage retry re-runs
        # the round cleanly. Degrading here would silently disable near-duplicate detection
        # for the whole round and insert paraphrases a retry would have caught.
        raise
    except Exception:
        # If the similarity check itself fails, don't block threat generation for it — just
        # act as if no duplicates were found. Raising here would lose every threat in the round.
        log.warning("threats.semantic_scan_failed", session_id=sid, subsystem=ss, exc_info=True)
        return {}
    dupes: dict[str, dict] = {}
    kept: list[str] = []  # survivors only — see the first-wins note in the docstring
    for tid, label, cat in entries:
        qv = vectors.get(label)
        if qv is None:
            kept.append(label)
            continue
        for other in prior + (kept if compare_within else []):
            ov = vectors.get(other)
            # No check to skip comparing an entry to itself — it isn't needed. `kept` only
            # gets an entry added after it's confirmed unique, and `prior` was read before
            # this batch existed, so self-comparison can't happen. (A previous version DID
            # guard against this by comparing label text, which accidentally also skipped two
            # genuinely different threats that happened to share identical labels — the
            # strongest possible duplicate signal, silently ignored.)
            if ov is None or len(ov) != len(qv):
                continue
            score = sum(x * y for x, y in zip(qv, ov)) / (norms[label] * norms[other])
            if score >= drop_threshold:
                dupes[tid] = {"reason": DuplicateReason.semantic_similarity, "score": score,
                            "duplicate_of_threat_id": tid_of.get(other)}
                log.info("threats.semantic_near_duplicate", session_id=sid, subsystem=ss,
                        proposed=label, matched=other, category=cat or None,
                        cosine=round(score, 4), threshold=drop_threshold)
                break
        else:
            kept.append(label)
    return dupes


def _build_threat_records(tid: str, sid: str, tenant: str, ss: int, ptype: str | None, pcat: str | None,
                        pname: str | None, gr: grounding.GroundingResult, entity_id: str | None,
                        user_id: str | None, generic_name: str | None = None,
                        category_id: int | None = None) -> tuple[dict, dict]:
    """Build the database row and the pipeline summary for one threat."""
    row = {
        "ThreatID": tid, "SessionID": sid, "TenantID": tenant, "EntityID": entity_id, "UserID": user_id,
        "SubsystemID": ss,
        "ThreatCategory": pcat, "ThreatType": ptype,
        "ThreatName": pname,
        # A generic (library-ready) version of ThreatName, saved so that later triage (when
        # this threat is accepted, maybe days later) uses the AI's own wording instead of a
        # rough text-stripping fallback. Cut to fit the column, so one overly long AI value
        # can't fail the whole batch insert and lose every threat in the round.
        "GenericName": generic_name[:500] if generic_name else None,
        # The category id grounding already resolved — stored so nothing downstream re-derives it
        # from ThreatCategory text. NULL when the AI's category matched no master row.
        "ThreatCategoryID": category_id,
        # actor_ids rides alongside actors so consumers read ids instead of re-resolving names.
        # Additive: grounding._actors_meta is the one parser, so stored_actors/validated_actors
        # are untouched, and legacy blobs simply lack the key.
        "ThreatActorsJSON": json.dumps({"actors": gr.actors, "actor_ids": gr.actor_ids,
                                        "validated": gr.actors_validated}),
        "LibraryThreatType": gr.library_type, "LibraryThreatName": gr.library_name,
        "ThreatTypeID": gr.type_id, "ThreatCatalogueID": gr.catalogue_id,
        # Immutable provenance, set once here (the ONLY threat-row writer): True <=> not in
        # the catalogue at identification. Promotion stamps ThreatCatalogueID later but
        # must not rewrite history by touching this.
        "IsThreatAIGenerated": gr.catalogue_id is None,
        # Same rule, type-level: True <=> the TYPE was not a library match at identification.
        # A separate fact from the catalogue-level one above — promotion mints ThreatTypeID
        # later but must not rewrite history by touching this either.
        "IsThreatTypeAIGenerated": gr.type_id is None,
        "GroundingStatus": gr.status, "GroundingScore": gr.score,
        # WHICH cutoff produced GroundingStatus. Without it, a 78 graded `verified` under the
        # untuned default 75.0 is indistinguishable from one graded under a measured 86.25 — so
        # once a deployment finally calibrates, the threats decided on the wrong number are
        # unfindable. Same provenance-as-a-column reasoning as Threat_Scenario_Control_Map's
        # min_score_origin.
        "GroundingThresholdOrigin": gr.threshold_origin,
        "Superseded": 0, "CreatedAt": dal.now(),
    }
    summary = {
        "threat_id": tid, "grounding_status": str(gr.status),
        # STRIDE category (Spoofing/Tampering/etc.), kept so the near-duplicate scan can
        # compare threats only within the same category — needed because two genuinely
        # different threats can still score higher on text similarity than real paraphrases
        # do (see _semantic_duplicates). Same key name used by dal.active_threats.
        "category": pcat,
        "threat_type": ptype, "threat_name": pname,
        "library_threat_type": gr.library_type, "library_threat_name": gr.library_name,
        "threat_type_id": gr.type_id,
        "catalogue_id": gr.catalogue_id,
        "is_ai_generated": gr.catalogue_id is None,
        "actors": gr.actors,
    }
    return row, summary


def _duplicate_row(row: dict, reason: DuplicateReason, *,
                    duplicate_of: str | None = None, score: float | None = None) -> dict:
    """Reshape a dropped threat's row for the duplicates audit table.

    An Identified_Threat row, reshaped for Identified_Duplicate_Threat — same proposed
    content, minus the library-grounding/scoring columns that table doesn't have, plus why it
    was dropped and (when known) what it matched. Audit-only; never read by the pipeline."""
    return {
        "DuplicateThreatID": row["ThreatID"], "SessionID": row["SessionID"],
        "TenantID": row["TenantID"], "EntityID": row["EntityID"], "UserID": row["UserID"],
        "SubsystemID": row["SubsystemID"],
        "ThreatCategory": row["ThreatCategory"], "ThreatType": row["ThreatType"],
        "ThreatName": row["ThreatName"], "GenericName": row["GenericName"],
        "ThreatActorsJSON": row["ThreatActorsJSON"],
        "DuplicateOfThreatID": duplicate_of, "DuplicateReason": str(reason),
        "SimilarityScore": score, "CreatedAt": row["CreatedAt"],
    }


def _generic_name_of(p: dict, asset_name: str) -> str | None:
    """Get a library-safe threat name with the asset name removed.

    Get the library-ready name for a Stage-1 proposal. Prefers the AI's own
    "generic_name" field, but only if it passes clean_library_name and doesn't contain the
    asset name — we don't trust the prompt alone to enforce that. Falls back to stripping
    the asset name out of the regular "name" field, which is also used by the near-duplicate
    scan, so both stay consistent about what counts as asset-agnostic."""
    pat = _asset_boundary_pattern(asset_name)
    g = clean_library_name(_safe_text(p.get("generic_name"), None))
    if g and pat and pat.search(g):
        log.warning("threats.generic_name_leaks_asset", generic_name=g)
        g = None
    return g or asset_agnostic_name(_safe_text(p.get("name"), None), asset_name)


def _usable_proposal(p: object) -> bool:
    """Check that one AI threat proposal is safe to save.

    Is this one item from the LLM's JSON list safe to save?

    We only checked that the response is a list overall — each item inside could still be
    junk. This filters out three kinds of junk before they cause damage further downstream:

    * Not a dict -> later code calling `.get()` on it crashes with the wrong kind of error,
      which cancels the whole session instead of failing gracefully.
    * Missing type/name -> there's nothing to match, score, or de-duplicate against, and it
      would keep failing the same way on every retry with no way to fix it.
    * Too long -> generating its embedding fails and takes down all the other threats found
      in that same batch with it.
    """
    if not isinstance(p, dict):
        return False
    ptype = _safe_text(p.get("type"), "") or ""
    pname = _safe_text(p.get("name"), "") or ""
    return bool(ptype) and bool(pname) and len(ptype) + len(pname) <= get_settings().max_proposal_chars


def _usable_category(p: dict, cats: list[str]) -> bool:
    """Check that the proposal's STRIDE category is a real, active one.

    Enum validation for one LLM threat proposal: its category must name one of the
    ACTIVE STRIDE categories, or the proposal is dropped before grounding — an invented
    category would otherwise be stored verbatim and silently fall outside every quota,
    coverage and distribution computation. An unseeded category table (cats empty) skips
    the check — the same degradation the quota path takes."""
    if not cats:
        return True
    c = _safe_text(p.get("category"), "") or ""
    return c.strip().casefold() in {x.strip().casefold() for x in cats}


def _build_retrieved_records(cand: dict, sid: str, tenant: str, ss: int,
                            scenario_session: dict, assigned_category: str,
                            category_id: int | None = None) -> tuple[dict, dict]:
    """Build the database row and summary for a gate-admitted library candidate.

    Identified_Threat row + pipeline summary for one gate-admitted library candidate.

    The candidate IS the library row, so grounding is identity, not similarity:
    verified, GroundingScore 100.0 (a real match confidence would imply a rerank that
    never ran), master ids and names on every column, and the type's LINKED actors with
    validated=True. Reuses _build_threat_records so the row shape cannot drift.

    `assigned_category` is the STRIDE cell this threat was SELECTED to fill
    (core.stride.assign), and it is what gets stored. It used to be `cand["categories"][0]`,
    and that one piece of positional convenience is the entire "everything is Denial of
    Service" bug: 74 of the 75 library rows are multi-category, the list arrived ordered by a
    ThreatCategoryID that the seed numbers alphabetically, and DoS holds id 1 — so it won every
    row it appeared on while Spoofing (5) and Tampering (6) won none. The caller now decides
    which of a threat's genuine categories it is being used for, and passes it in. See
    core/stride.py."""
    gr = grounding.GroundingResult(
        status=GroundingStatus.verified, type_id=cand["type_id"],
        catalogue_id=cand["catalogue_id"], library_type=cand["type_name"],
        library_name=cand["threat_name"], score=100.0,
        actors=cand["actors"], actor_ids=cand.get("actor_ids") or [], actors_validated=True,
        category_id=category_id,
        # Library-first: this candidate IS a library row, matched by identity, so NO cutoff was
        # ever consulted (the score above is a literal 100.0, not a rerank). An explicit marker
        # rather than NULL — NULL means "written before this column existed", and folding these
        # rows into that bucket makes it unreadable exactly when someone is trying to find which
        # threats a wrong threshold judged.
        threshold_origin="not_applicable")
    pcat = (assigned_category or "")[:200]
    row, summary = _build_threat_records(
        guid(), sid, tenant, ss, cand["type_name"][:300], pcat, cand["threat_name"][:500],
        gr, scenario_session["EntityID"], scenario_session.get("UserID"),
        generic_name=cand["threat_name"],
        category_id=category_id)
    # Additive keys, ignored by _dedup_key/scoring: full multi-category membership for the
    # coverage grid, plus retrieval/gate provenance for the audit trail.
    summary["categories"] = cand.get("categories") or []
    # Retrieved-vs-generated provenance for the audit tallies ("hybrid" = came from the
    # register's ranked pool; generated threats carry no selection_source).
    summary["selection_source"] = cand.get("selection_source") or "hybrid"
    summary["retrieval_score"] = cand.get("retrieval_score")
    # The rerank-gate score (0-100) plus the gate verdict — with retrieval_score (the RRF
    # rank-sum) alongside, "why was this threat selected" is answerable per row.
    summary["relevance_score"] = cand.get("relevance_score")
    summary["gate_outcome"] = cand.get("gate_outcome")
    summary["catalogue_id"] = cand.get("catalogue_id")
    return row, summary


def _gap_ask(shortfall: int) -> int:
    """Work out how many threats to request so enough survive dedup.

    How many threats to REQUEST to reliably land `shortfall` NEW ones.

    Generation loses proposals to dedup — the model re-proposes threats the session already
    holds even though the exclusion list names every one of them. Asking for exactly the
    shortfall therefore guarantees under-delivery; asking for a multiple of it absorbs the loss
    inside the SAME single call.

    Bounded below by `shortfall` so a factor of 1.0 disables the buffer rather than inverting it.
    `gap_generation_buffer` is a setting so a deployment seeing shortfalls can raise it without a
    code change — the right multiple depends on how repetitive the model is against that library.
    """
    return max(shortfall, math.ceil(shortfall * get_settings().gap_generation_buffer))


# ---------------------------------------------------------------------------------------
# The identification round: shared working state + one function per stage
# ---------------------------------------------------------------------------------------

@dataclass
class _IdentificationRound:
    """Working state for one threat-identification round.

    Mutable working state for ONE identification round — a data record passed
    explicitly between the stage functions below (never module state, never behavior)."""
    candidates: list[dict] = field(default_factory=list)     # gate-passed, best-first
    backfill_pool: list[dict] = field(default_factory=list)  # below-threshold, score order
    gate_failed: bool = False
    rows: list[dict] = field(default_factory=list)
    threats: list[dict] = field(default_factory=list)
    retrieved_summaries: list[dict] = field(default_factory=list)
    dup_rows: list[dict] = field(default_factory=list)       # audit-only, see _duplicate_row
    existing_identities: dict[str, str] = field(default_factory=dict)
    attribution: dict[str, list[int]] = field(default_factory=dict)  # ThreatID -> systems
    cat_id_memo: dict[str, int | None] = field(default_factory=dict)
    duplicates: int = 0
    retrieved_near_dupes: int = 0

    def resolve_category_id(self, sess: Session, cat: str) -> int | None:
        """Turn a STRIDE category name into its database id (cached per round).

        Resolve a STRIDE name to its id ONCE per round — a handful of queries, not one
        per candidate. The one resolver every writer (pass 1, relabel, backfill) shares,
        so the two category columns can never disagree about a name's id."""
        if cat not in self.cat_id_memo:
            self.cat_id_memo[cat] = grounding.find_category(sess, cat) if cat else None
        return self.cat_id_memo[cat]


class _GapGenerationResult(NamedTuple):
    """What one gap-generation call produced."""
    proposals: list
    prov: Provenance | None
    llm_failed: bool
    gap_ask: int


def _embed_retrieval_queries(llm: LLMClient, sid: str, subsystems: list[dict],
                        asset_context: dict) -> tuple[list[str], list | None]:
    """Build and embed the retrieval queries once for the whole round.

    ONE query-embed round for the whole funnel: retrieval and the gate score the SAME
    queries, so they are embedded once here and the vectors handed to both. A non-slot
    embed failure passes None and each half falls back on its own (retrieval's
    keyword-only degradation, the gate's fail-open) — same behavior, half the IO."""
    queries = threat_retrieval.build_queries(subsystems, asset_context)
    qvs: list | None = None
    if queries:
        try:
            vecs = llm.embed(queries, kind="query")
            if len(vecs) == len(queries):
                qvs = list(vecs)
        except LLMSlotUnavailable:
            raise
        except Exception:
            log.warning("threats.query_embed_failed", session_id=sid, exc_info=True)
    return queries, qvs


def _apply_relevance_gate(r: _IdentificationRound, sess: Session, llm: LLMClient, sid: str,
                    candidates: list[dict], subsystems: list[dict], asset_context: dict,
                    s_cfg, queries: list[str], qvs: list | None,
                    gate_threshold: float) -> None:
    """Split candidates into relevant vs backfill using the reranker score.

    Top-K rerank relevance gate. Splits the pool into r.candidates (first-class) and
    r.backfill_pool (below-threshold, kept flagged); a gate OUTAGE fails open to the
    ungated pool with r.gate_failed recorded — a rerank blip must weaken ranking, never
    silently shrink coverage (the contract the old LLM validator kept)."""
    if not candidates:
        return
    with trace_step("RELEVANCE GATE", sid, candidates=len(candidates),
                    threshold=gate_threshold) as _t:
        scores: dict[int, float] = {}
        try:
            scores = threat_retrieval.score_relevance(
                llm, candidates, subsystems, asset_context, s_cfg,
                queries=queries, query_vecs=qvs)
        except LLMSlotUnavailable:
            raise
        except Exception:
            r.gate_failed = True
            sess.rollback()
            log.warning("threat_retrieval.rerank_failed_gate_skipped",
                        session_id=sid, exc_info=True)
        # gate_outcome is stamped SEPARATELY from selection_source: the retrieval leg
        # ("hybrid") and the gate verdict are orthogonal provenance facts — folding them
        # into one field made "which threats came in below the bar?" unanswerable.
        for c in candidates:
            c["relevance_score"] = scores.get(c["catalogue_id"])
            if r.gate_failed:
                c["ranking_degraded"] = True
                c["gate_outcome"] = "ungated"
        if r.gate_failed:
            r.candidates = list(candidates)
        else:
            # Best-first by RERANK score — the one defined relevance measure; stride.assign
            # preserves this order within each category. Below-threshold candidates are NOT
            # discarded: they are the flagged BACKFILL pool that guarantees the requested
            # count. The threshold itself is never lowered.
            ranked = sorted(candidates, key=lambda c: (
                -(c["relevance_score"] or 0.0), c["catalogue_id"]))
            r.candidates = [c for c in ranked
                            if (c["relevance_score"] or 0.0) >= gate_threshold]
            r.backfill_pool = [c for c in ranked
                            if (c["relevance_score"] or 0.0) < gate_threshold]
            for c in r.candidates:
                c["gate_outcome"] = "passed"
            for c in r.backfill_pool:
                c["gate_outcome"] = "below_threshold"
        _t.result(kept=len(r.candidates), below_threshold=len(r.backfill_pool),
                gate_failed=r.gate_failed)


def _held_category_counts(sess: Session, sid: str, ss: int, supersede: bool,
                    prior_threats: list[dict] | None) -> dict[str, int]:
    """Count how many threats the session already holds per STRIDE category.

    What the session ALREADY holds per category. An additive round (next-set, regen)
    must top up what is thin rather than restart at Spoofing, so the quota is computed
    against reality, not an empty grid.

    Counted from the STORED category, one per threat — deliberately NOT from
    active_threat_grid_categories, which returns the full multi-category membership and
    would count a 3-category threat three times. That grid is the right unit for coverage
    accounting (does any threat answer this cell?) and the wrong one here, where a slot is
    what is being allocated. prior_threats is this same read, already done by the additive
    caller — reused rather than re-queried. Asset unit only: the subsystem rows are
    fan-out copies of these same threats (Phase 2b)."""
    held: dict[str, int] = {}
    if not supersede:
        prior = prior_threats if prior_threats is not None else dal.active_threats(sess, sid, ss)
        for t in prior:
            c = t.get("category")
            if c:
                held[c] = held.get(c, 0) + 1
    return held


def _select_library_candidates(sid: str, r: _IdentificationRound, target: dict[str, int],
                    max_threats: int) -> list[tuple[dict, str]]:
    """Pick library candidates to fill the STRIDE quota.

    Pass-1 STRIDE-aware selection over the gated library pool. The quota decides how
    many slots each category gets and assignment decides which candidate fills each slot —
    selection and labelling are ONE decision, and the spread is a property of the
    algorithm. Score still orders candidates WITHIN a category."""
    with trace_step("STRIDE QUOTA", sid, target=target,
                    candidates=len(r.candidates)) as _t:
        if target:
            selected = stride.assign(r.candidates, target, lambda c: c.get("categories") or [])
        else:
            # No categories to allocate against — an UNSEEDED Threat_Category table, which
            # dal.active_category_names documents as a supported state. Quota-driven
            # selection would return nothing at all here, so it degrades to the pre-quota
            # behaviour: best-ranked first, up to the cap. Losing the spread on an unseeded
            # DB is a weaker answer; returning no threats would be a silent outage, and this
            # codebase never trades the second for the first.
            # invariants._assert_stride_categories warns about this at boot.
            log.warning("threats.quota_skipped_no_categories", session_id=sid, cap=max_threats)
            selected = [(c, (c.get("categories") or [""])[0]) for c in r.candidates[:max_threats]]
        _t.result(assigned=stride.achieved(selected), selected=len(selected))
    return selected


def _admit_selected_candidates(r: _IdentificationRound, sess: Session, sid: str, tenant: str, ss: int,
                    scenario_session: dict, selected: list[tuple[dict, str]]) -> None:
    """Save the picked candidates into the round, skipping ones already held.

    Build records for the pass-1 winners, identity-deduped: a candidate already active
    on the session (an additive round re-retrieving the library) is a no-op, not an
    audit-worthy duplicate."""
    for cand, assigned_category in selected:
        row, summary = _build_retrieved_records(cand, sid, tenant, ss, scenario_session,
                                                assigned_category,
                                                category_id=r.resolve_category_id(sess, assigned_category))
        identity = dal.identity_hash(sid, ss, summary)
        if identity in r.existing_identities:
            continue
        r.existing_identities[identity] = row["ThreatID"]
        r.attribution[row["ThreatID"]] = cand.get("subsystem_ids") or []
        r.rows.append(row)
        r.threats.append(summary)
        r.retrieved_summaries.append(summary)


def _drop_prior_paraphrases(r: _IdentificationRound, llm: LLMClient, sid: str, ss: int,
                            scenario_session: dict, tn,
                            prior_threats: list[dict] | None) -> None:
    """Drop picked candidates that just reword a previous round's threat.

    A retrieved LIBRARY candidate is identity-checked against what's active, but never
    against a PRIOR round's near-duplicate paraphrase — a prior round may have GENERATED a
    threat with different wording, so identity_hash alone misses it. On the additive path
    prior_threats carries exactly those rows; scan retrieved candidates against them too.
    Retrieved-vs-retrieved stays exempt (compare_within=False): two distinct library rows
    surviving together is the curator's call, not this scan's."""
    if not (prior_threats and r.retrieved_summaries):
        return
    retrieved_dupes = _semantic_duplicates(llm, sid, ss, r.retrieved_summaries, prior_threats,
                                            scenario_session["AssetName"],
                                            threshold=tn.semantic_near_duplicate_threshold,
                                            compare_within=False)
    if not retrieved_dupes:
        return
    r.retrieved_near_dupes = len(retrieved_dupes)
    by_id = {row["ThreatID"]: row for row in r.rows}
    r.dup_rows.extend(
        _duplicate_row(by_id[tid], info["reason"],
                    duplicate_of=info["duplicate_of_threat_id"], score=info["score"])
        for tid, info in retrieved_dupes.items() if tid in by_id)
    # Release the dropped rows' identity claims: nothing referencing them is ever inserted,
    # and a claimed-but-absent identity blocks backfill into a false PARTIAL. Genuine
    # paraphrases stay blocked by backfill's own semantic scan.
    for t in r.retrieved_summaries:
        if t["threat_id"] in retrieved_dupes:
            r.existing_identities.pop(dal.identity_hash(sid, ss, t), None)
    r.rows = [row for row in r.rows if row["ThreatID"] not in retrieved_dupes]
    r.threats = [t for t in r.threats if t["threat_id"] not in retrieved_dupes]
    r.retrieved_summaries = [t for t in r.retrieved_summaries
                            if t["threat_id"] not in retrieved_dupes]
    log.info("threats.retrieved_semantic_duplicates_dropped", session_id=sid, subsystem=ss,
            dropped=r.retrieved_near_dupes)


def _evaluate_coverage(r: _IdentificationRound, target: dict[str, int],
                    max_threats: int) -> tuple[int, dict[str, int], int]:
    """Work out how many threats are missing, by count and by category.

    Count alone does not decide sufficiency: pass-1 assignment reallocates unservable
    slots softly, so six same-category library threats can "satisfy" a count of six while
    whole STRIDE cells sit empty. Sufficiency therefore checks BOTH the quantity gap and
    the target cells the library left unserved; generation covers the larger of the two,
    and the terminal selection then swaps a generated thin-category threat in."""
    achieved_now = stride.achieved(
        [(None, t["category"]) for t in r.threats if t.get("category")])
    quantity_gap = max(0, max_threats - len(r.rows))
    coverage_missing = {c: k - achieved_now.get(c, 0) for c, k in target.items()
                        if achieved_now.get(c, 0) < k}
    return quantity_gap, coverage_missing, max(quantity_gap, sum(coverage_missing.values()))


def _generate_gap_proposals(r: _IdentificationRound, sess: Session, llm: LLMClient, sid: str, ss: int,
                scenario_session: dict, subsystems: list[dict], asset_context: dict,
                cats: list[str], held: dict[str, int], exclude: list[str] | None,
                quantity_gap: int, coverage_missing: dict[str, int], gap_need: int,
                epoch: int, task_id: str, s_cfg, max_threats: int) -> _GapGenerationResult:
    """Ask the LLM once for threats to fill the gap.

    Stage 1b: ONE bounded LLM call for ONLY what the library did not fill. The
    per-category quota names the thin categories in the prompt; the ask is buffered
    (dedup eats re-proposals) but hard-capped by threat_llm_max_generation. A provider
    failure keeps the library results (PARTIAL at worst, decided later); the slot signal
    always propagates to the Celery stage retry."""
    if gap_need <= 0:
        log.info("threats.generation_skipped_library_filled", session_id=sid, cap=max_threats)
        return _GapGenerationResult([], None, False, 0)
    exclude_all = list(exclude or []) + [
        t["threat_name"] for t in r.retrieved_summaries if t.get("threat_name")]
    # The per-category quota for the GAP, allocated against what the session holds now
    # (what it already had, plus what assignment just retrieved) — the categories the
    # curated library could not supply are exactly the ones still thin, so they are the
    # ones this quota names in the prompt.
    have = dict(held)
    for t in r.retrieved_summaries:
        c = t.get("category")
        if c:
            have[c] = have.get(c, 0) + 1
    # ASK FOR MORE THAN THE GAP (dedup eats re-proposals; asking for exactly the gap
    # structurally under-delivers), but never past the hard ceiling —
    # threat_llm_max_generation bounds ONE call whatever the arithmetic says. The terminal
    # selection trims any surplus, so over-supply costs tokens only.
    gap_ask = min(_gap_ask(gap_need), s_cfg.threat_llm_max_generation)
    gap_quota = stride.allocate(gap_ask, cats, existing=have)
    gap_gen_messages = prompts.threats_prompt(
        scenario_session["AssetName"], asset_context, subsystems,
        max_threats=gap_ask, categories=cats, exclude=exclude_all or None,
        quota=gap_quota)
    proposals: list = []
    prov: Provenance | None = None
    llm_failed = False
    # `messages` is deliberately NOT traced: _ask_ai already persists the whole prompt to
    # Prompt_Log, and dumping it again here would put the full asset context in a second
    # place that has no retention policy.
    with trace_step("GAP GENERATION", sid, quantity_gap=quantity_gap,
                    coverage_missing=coverage_missing, gap_ask=gap_ask, categories=cats,
                    exclude=exclude_all, prompt_messages=len(gap_gen_messages)) as _t:
        try:
            proposals, prov = _ask_ai(sess, llm, gap_gen_messages,
                                    scenario_session=scenario_session, subsystem_id=ss, stage="threats",
                                    level=SubsystemLevel.THREATS, epoch=epoch, task_id=task_id, expected_type=list,
                                    temperature=get_settings().threat_identification_temperature)
        except LLMSlotUnavailable:
            raise  # codebase-wide contract: the Celery stage retry resumes via the CAS
        except Exception:
            # A provider failure must not destroy the valid library results already in
            # hand: keep them, let the backfill chase the requested count, and record
            # PARTIAL only if it still falls short.
            llm_failed = True
            proposals = []
            sess.rollback()
            log.warning("threats.gap_generation_failed", session_id=sid,
                        gap_ask=gap_ask, exc_info=True)
        # Filter untrusted LLM output once here (see _usable_proposal) rather than in every
        # place that reads it below — the only spot that covers every reader, including
        # grounding.prime_query_embeddings.
        raw_proposal_count = len(proposals)
        usable = [p for p in proposals if _usable_proposal(p) and _usable_category(p, cats)]
        if len(usable) != len(proposals):
            log.warning("threats.proposals_dropped", session_id=sid,
                        dropped=len(proposals) - len(usable), received=len(proposals))
        proposals = usable
        _t.result(raw_proposal_count=raw_proposal_count, usable_proposals=proposals,
                llm_failed=llm_failed)
    return _GapGenerationResult(proposals, prov, llm_failed, gap_ask)


def _ground_and_admit_proposals(r: _IdentificationRound, sess: Session, llm: LLMClient, sid: str, tenant: str,
                    ss: int, scenario_session: dict, proposals: list,
                    epoch: int, task_id: str) -> None:
    """Match each proposal against the library and admit the new ones.

    Structural validation happened in _generate_gap_proposals; here every usable proposal is
    grounded against the library (a verified match adopts the canonical catalogue
    identity; no match = custom candidate) and identity-deduped. No early count-break:
    grounding + dedup are cheap local work bounded by threat_llm_max_generation, and the
    terminal STRIDE selection decides which survive — a generated thin-category threat
    must be able to displace a surplus same-category one."""
    grounding_cache: dict = {}
    # Grounding and the identity fingerprint both run on the library-ready name: the AI's
    # own generic_name if valid, otherwise a stripped-down fallback (_generic_name_of).
    to_ground = [{**p, "name": _generic_name_of(p, scenario_session["AssetName"])}
                for p in proposals]  # safe: _usable_proposal guaranteed these are dicts
    grounding.prime_query_embeddings(llm, to_ground, grounding_cache)
    rows_before = len(r.rows)
    for p, gp in zip(proposals, to_ground):
        if not dal.renew_lease(sess, sid, ss, SubsystemLevel.THREATS, epoch, task_id):
            log.warning("stage.lease_renewal_failed", session_id=sid, subsystem=ss,
                        level=str(SubsystemLevel.THREATS))
        sess.commit()
        # Clip these values to fit their DB columns right here, not later when building the
        # row: an over-long AI value would otherwise fail the whole batch insert (losing
        # every threat in the round), and clipping afterward would make the stored value
        # disagree with the identity hash computed from these same variables.
        ptype = _safe_text(p.get("type"), "")[:300]
        pcat = _safe_text(p.get("category"), "")[:200]
        pname = _safe_text(p.get("name"), None)
        if pname:
            pname = pname[:500]
        with trace_step("REGROUNDING", sid, proposal=p, generic_proposal=gp) as _t:
            gr = grounding.find_threat_in_library(sess, llm, gp, cache=grounding_cache)
            _t.result(grounding_result=gr)
        tid = guid()
        row, summary = _build_threat_records(tid, sid, tenant, ss, ptype, pcat, pname, gr,
                                        scenario_session["EntityID"], scenario_session.get("UserID"),
                                        generic_name=gp.get("name") if isinstance(gp, dict) else None,
                                        category_id=gr.category_id)
        # (The old GAP-B "validator reversal" block is gone with the validator itself: a
        # relevance-gate miss is a score, not a reviewable NOT_RELEVANT verdict, so a
        # generated proposal regrounding onto a below-gate catalogue row is legitimate
        # evidence of relevance, not a reversal. DuplicateReason.validator_rejected
        # survives in enums.py so historical audit rows stay readable.)
        identity = dal.identity_hash(sid, ss, summary)
        if identity in r.existing_identities:
            r.duplicates += 1
            r.dup_rows.append(_duplicate_row(row, DuplicateReason.identity,
                                            duplicate_of=r.existing_identities.get(identity)))
            continue
        r.existing_identities[identity] = tid
        r.rows.append(row)
        r.threats.append(summary)
    with trace_step("REGROUNDING SUMMARY", sid, proposals_considered=len(proposals)) as _t:
        _t.result(identity_duplicates=r.duplicates,
                threats_added=len(r.rows) - rows_before)


def _drop_generated_duplicates(r: _IdentificationRound, llm: LLMClient, sid: str, ss: int,
                            scenario_session: dict, tn,
                            prior_threats: list[dict] | None) -> int:
    """Drop generated threats that duplicate existing ones.

    Near-duplicate check BEFORE inserting, so it can actually block bad rows — the
    exact-match check only catches identical wording. GENERATED summaries only: retrieved
    threats are curated library rows whose distinctness the curator vouched for; the
    retrieved set rides as PRIORS instead, so a generated paraphrase of a library threat
    is dropped (and attributed to the library row it duplicates). Disable without a
    deploy by setting semantic_near_duplicate_threshold to 1.0."""
    retrieved_ids = {t["threat_id"] for t in r.retrieved_summaries}
    generated_summaries = [t for t in r.threats if t["threat_id"] not in retrieved_ids]
    dupe_info = _semantic_duplicates(llm, sid, ss, generated_summaries,
                                    (prior_threats or []) + r.retrieved_summaries,
                                    scenario_session["AssetName"],
                                    threshold=tn.semantic_near_duplicate_threshold)
    if not dupe_info:
        return 0
    by_id = {row["ThreatID"]: row for row in r.rows}
    r.dup_rows.extend(
        _duplicate_row(by_id[tid], info["reason"],
                    duplicate_of=info["duplicate_of_threat_id"], score=info["score"])
        for tid, info in dupe_info.items() if tid in by_id)
    # Same identity release as the retrieved-vs-prior scan: a generated proposal that
    # grounded onto catalogue row N and was then dropped must not leave `cat:N` claimed —
    # that skipped candidate N at backfill and reported a false PARTIAL.
    for t in r.threats:
        if t["threat_id"] in dupe_info:
            r.existing_identities.pop(dal.identity_hash(sid, ss, t), None)
    r.rows = [row for row in r.rows if row["ThreatID"] not in dupe_info]
    r.threats = [t for t in r.threats if t["threat_id"] not in dupe_info]
    log.info("threats.semantic_duplicates_dropped", session_id=sid, subsystem=ss,
            dropped=len(dupe_info))
    return len(dupe_info)


def _finalize_stride_selection(r: _IdentificationRound, sess: Session, target: dict[str, int],
                        max_threats: int) -> tuple[list, set[str], list[dict]]:
    """Pick the final balanced set from library + generated threats.

    FINAL STRIDE-aware selection over the merged pool (library + generated). Pass 1
    balanced the library slice and gap_quota steered generation, but only this terminal
    pass sees BOTH: it trims generation surplus and lets a generated thin-category threat
    displace a soft-reallocated over-represented library one. `r.threats` is already
    library-first (retrieved appended before generated), so a library candidate wins any
    category slot both could fill. Terminal assignment is authoritative for the STORED
    category — selection and labelling are one decision, same rule as pass 1. Rows are
    still plain dicts (the insert happens later), so relabelling mutates in place."""
    def _cats_of(t: dict) -> list:
        return t.get("categories") or ([t["category"]] if t.get("category") else [])

    final_pairs = (stride.assign(r.threats, target, _cats_of) if target
                else [(t, t.get("category") or "") for t in r.threats[:max_threats]])
    rows_by_id = {row["ThreatID"]: row for row in r.rows}
    kept_ids: set[str] = set()
    for t, cat in final_pairs:
        kept_ids.add(t["threat_id"])
        if cat and t.get("category") != cat:
            t["category"] = cat
            row = rows_by_id[t["threat_id"]]
            row["ThreatCategory"] = cat[:200]
            # BOTH category columns move together — promote reads ThreatCategoryID straight
            # off the row, so relabelling only the text would re-open the "everything is
            # DoS" bug through the id column. Same memo the pass-1 builder used.
            row["ThreatCategoryID"] = r.resolve_category_id(sess, cat)
    surplus = [t for t in r.threats if t["threat_id"] not in kept_ids]
    return final_pairs, kept_ids, surplus


def _backfill_to_count(r: _IdentificationRound, sess: Session, llm: LLMClient, sid: str, tenant: str,
                    ss: int, scenario_session: dict, tn,
                    prior_threats: list[dict] | None, target: dict[str, int],
                    final_pairs: list, kept_ids: set[str], surplus: list[dict],
                    max_threats: int) -> tuple[int, int]:
    """Top up to the requested count with flagged weaker candidates.

    COUNT BACKFILL: the requested count is always met (user rule). The relevance
    threshold is never lowered — weaker entries come in EXPLICITLY FLAGGED instead.
    Order: trimmed surplus (already-built, above-gate work), then library candidates —
    coverage-first (unfilled STRIDE cells via the same assigner every other selection
    uses), then best-score padding. Returns (backfilled, semantic_blocked)."""
    backfilled = 0
    blocked_count = 0
    need = max_threats - len(kept_ids)
    for t in surplus:
        if need <= 0:
            break
        kept_ids.add(t["threat_id"])
        t["backfill"] = True
        backfilled += 1
        need -= 1
    if need <= 0:
        return backfilled, blocked_count
    # Eligible pool: identity-new candidates, above-threshold leftovers before the
    # below-threshold pool (each already best-score-first). identity_hash is the ONE guard
    # (its cat:{id} rung also covers rows a generated proposal grounded onto).
    pool: list[dict] = []
    pool_cids: set[int] = set()
    for cand in r.candidates + r.backfill_pool:
        cid = cand["catalogue_id"]
        if cid in pool_cids:
            continue
        pool_cids.add(cid)
        if dal.identity_hash(sid, ss, {"catalogue_id": cid}) not in r.existing_identities:
            pool.append(cand)
    # The pool must clear the SAME semantic bar everything else did: a below-gate
    # paraphrase of a prior-round (or just-kept) threat must not ride in through backfill
    # when both dedup scans above have already run. One batched scan.
    kept_now = [t for t in r.threats if t["threat_id"] in kept_ids]
    if pool and (prior_threats or kept_now):
        light = [{"threat_id": f"cand:{c['catalogue_id']}",
                "threat_name": c["threat_name"],
                "category": (c.get("categories") or [""])[0]} for c in pool]
        blocked = _semantic_duplicates(llm, sid, ss, light,
                                    (prior_threats or []) + kept_now,
                                    scenario_session["AssetName"],
                                    threshold=tn.semantic_near_duplicate_threshold,
                                    compare_within=False)
        if blocked:
            blocked_count = len(blocked)
            pool = [c for c in pool if f"cand:{c['catalogue_id']}" not in blocked]
            log.info("threats.backfill_semantic_blocked", session_id=sid, subsystem=ss,
                    blocked=blocked_count)
    # Coverage-first: serve the STRIDE cells the terminal pass left unfilled through
    # stride.assign — selection and labelling stay ONE decision (a positional
    # categories[0] label here is the exact "everything is Spoofing" bug stride.py
    # documents) — then pad any remaining count by score with the same rule.
    achieved_final = stride.achieved(final_pairs)
    unfilled = {c: k - achieved_final.get(c, 0) for c, k in target.items()
                if achieved_final.get(c, 0) < k}
    ordered: list[tuple[dict, str]] = (
        stride.assign(pool, unfilled, lambda c: c.get("categories") or [])
        if unfilled else [])
    chosen = {id(c) for c, _cat in ordered}
    ordered += [(c, (c.get("categories") or [""])[0]) for c in pool if id(c) not in chosen]
    for cand, bf_category in ordered:
        if need <= 0:
            break
        identity = dal.identity_hash(sid, ss, {"catalogue_id": cand["catalogue_id"]})
        if identity in r.existing_identities:
            continue
        row, summary = _build_retrieved_records(cand, sid, tenant, ss, scenario_session,
                                                bf_category,
                                                category_id=r.resolve_category_id(sess, bf_category))
        r.existing_identities[identity] = row["ThreatID"]
        r.attribution[row["ThreatID"]] = cand.get("subsystem_ids") or []
        summary["backfill"] = True
        r.rows.append(row)
        r.threats.append(summary)
        r.retrieved_summaries.append(summary)
        kept_ids.add(summary["threat_id"])
        backfilled += 1
        need -= 1
    return backfilled, blocked_count


def _build_fanout_rows(r: _IdentificationRound, subsystems: list[dict], grid_subsystem_ids: list[int],
                retrieved_ids: set[str]) -> list[dict]:
    """Copy each threat row onto the supporting systems it applies to.

    Phase 2b fan-out. Built AFTER every dedup/selection pass so a dropped threat is
    dropped on every unit at once. The copies are records, not work: each gets its own
    ThreatID, and none is ever scored, scenario-generated or promoted — every one of
    those paths reads the asset unit."""
    summaries_by_id = {t["threat_id"]: t for t in r.threats}
    gen_attribution = threat_retrieval.attribute_to_subsystems(
        subsystems,
        [t["threat_type_id"] for t in r.threats
        if t["threat_id"] not in retrieved_ids and t.get("threat_type_id") is not None])
    fanout_rows: list[dict] = []
    for row in r.rows:
        t = summaries_by_id[row["ThreatID"]]
        if row["ThreatID"] in retrieved_ids:
            units = r.attribution.get(row["ThreatID"], [])
        else:
            # A generated threat that GROUNDED to a library type inherits that type's
            # gates; one that grounded to nothing has no narrowing evidence at all, so it
            # reaches everything. Same fail-open rule, applied to weaker evidence.
            units = gen_attribution.get(t.get("threat_type_id"), grid_subsystem_ids)
        for unit in units:
            fanout_rows.append({**row, "ThreatID": guid(), "SubsystemID": unit})
    return fanout_rows


def _build_coverage_detail(sess: Session, sid: str, ss: int, cats: list[str],
                    grid_subsystem_ids: list[int]) -> dict[str, Any]:
    """Build the optional session-coverage report for the audit record.

    TSG_COVERAGE_REPORTING_ENABLED, off by default — an advisory-only completeness
    signal that never gates any action. While off, nothing here runs at all: no grid
    query, no computation, no log line; the audit row simply omits "units"/"coverage".
    Read live from the DB, after the insert, so an additive round reports the SESSION's
    coverage rather than just this round's delta."""
    if not get_settings().coverage_reporting_enabled:
        return {}
    coverage_units = [ss, *grid_subsystem_ids]
    with trace_step("COVERAGE", sid, unit_ids=coverage_units, categories=cats) as _t:
        grid_records = dal.active_threat_grid_categories(sess, sid, coverage_units)
        cov = coverage.coverage_report(coverage_units, cats, grid_records)
        _t.result(grid_records=len(grid_records), coverage_report=cov)
    if cov["unexplained"]:
        log.warning("threats.coverage_gaps", session_id=sid, subsystem=ss,
                    units=1 + len(grid_subsystem_ids),
                    unexplained=cov["unexplained"], gaps=cov["gaps"][:12])
    return {"units": coverage_units, "coverage": {**cov, "gaps": cov["gaps"][:50]}}


def _build_audit_payload(r: _IdentificationRound, *, status: str, requested: int, delivered: int,
                backfilled: int, blocked: int, backfilled_threats: list[dict],
                quantity_gap: int, coverage_missing: dict[str, int],
                gate_threshold: float, gap: _GapGenerationResult, gap_need: int, near_dupes: int,
                target: dict[str, int], fanout_count: int,
                coverage_detail: dict[str, Any]) -> dict:
    """Build the audit JSON that explains everything this round did.

    The grounding_summary DetailJSON — the COMPLETE/PARTIAL contract plus everything
    needed to answer "why was this threat (not) selected" after the fact. Recorded, not
    just logged: a degraded or skewed run must be answerable from data afterwards."""
    ranking_degraded = any(c.get("ranking_degraded") for c in r.candidates) or \
        any(c.get("ranking_degraded") for c in r.backfill_pool) or r.gate_failed
    selection_sources: dict[str, int] = {}
    for t in r.retrieved_summaries:
        key = t.get("selection_source") or "hybrid"
        selection_sources[key] = selection_sources.get(key, 0) + 1
    if len(r.threats) > len(r.retrieved_summaries):
        selection_sources["generated"] = len(r.threats) - len(r.retrieved_summaries)
    # The distribution this round actually produced, by STORED category — the number the
    # "everything is Denial of Service" report was about. The coverage grid reads the FULL
    # multi-category membership and looked healthy while every visible label said DoS.
    distribution = stride.achieved(
        [(None, t["category"]) for t in r.threats if t.get("category")])
    return {"count": len(r.threats),
            "selection_sources": selection_sources,
            "ranking_degraded": ranking_degraded,
            "subsystem_records": fanout_count,
            "retrieved": len(r.retrieved_summaries),
            "generated": len(r.threats) - len(r.retrieved_summaries),
            "status": status,
            "requested": requested,
            "delivered": delivered,
            "backfilled": backfilled,
            "backfilled_threats": backfilled_threats,
            "backfill_semantic_blocked": blocked,
            "quantity_gap": quantity_gap,
            "coverage_missing": coverage_missing,
            "relevance_threshold": gate_threshold,
            "gate": {"pool": len(r.candidates) + len(r.backfill_pool),
                    "relevant": len(r.candidates),
                    "below_threshold": len(r.backfill_pool),
                    "gate_failed": r.gate_failed},
            "llm": {"fallback_used": gap_need > 0,
                    "failed": gap.llm_failed,
                    "requested": gap.gap_ask,
                    "usable": len(gap.proposals)},
            "identity_duplicates": r.duplicates,
            "semantic_near_duplicates": near_dupes,
            "retrieved_semantic_duplicates": r.retrieved_near_dupes,
            "stride_target": target,
            "stride_distribution": distribution,
            **coverage_detail}


def find_threats(sess: Session, scenario_session: dict, subsystems: list[dict], asset_context: dict, llm: LLMClient, task_id: str,
                epoch: int = _EPOCH, categories: list[str] | None = None,
                actor_examples: list[str] | None = None,
                supersede: bool = True, exclude: list[str] | None = None,
                prior_threats: list[dict] | None = None,
                max_threats: int | None = None) -> tuple[list[dict], Provenance | None]:
    """Run one full Stage-1 threat-identification round, start to finish.

    Stage-1 orchestrator — each step is a single-responsibility function above.

    `exclude` is label text used to steer the prompt away from repeats. `prior_threats` is
    those same threats as full rows (with category), needed for the near-duplicate scans.
    The caller already has both, so passing them in costs no extra query. An
    infrastructure failure in retrieval PROPAGATES to the Celery stage retry — never
    silently read as "library empty"."""
    sid, ss, tenant = scenario_session["SessionID"], ASSET_UNIT_ID, scenario_session["TenantID"]
    with trace_step("ASSET CONTEXT", sid, asset_context=asset_context,
                    subsystems=subsystems):
        pass          # input-only marker: the context is already built when find_threats runs
    if not dal.claim_stage(sess, sid, ss, SubsystemLevel.THREATS, epoch, task_id):
        return [], None
    sess.commit()
    _send_live_update(sid, SSEEventType.stage_started, ss, SubsystemLevel.THREATS, StageStatus.RUNNING, epoch)
    tn = tuning.from_session(scenario_session)  # frozen at session start, not live config
    if max_threats is None:
        max_threats = tn.max_threats_per_asset
    cats = categories if categories is not None else dal.active_category_names(sess)
    grid_subsystem_ids = threat_retrieval.all_subsystem_ids(subsystems)
    s_cfg = get_settings()

    # Stage 1a: library-first retrieval + local rerank relevance gate.
    queries, qvs = _embed_retrieval_queries(llm, sid, subsystems, asset_context)
    candidates = threat_retrieval.retrieve_library_threats(
        sess, llm, subsystems, asset_context, session_id=sid,
        queries=queries, query_vecs=qvs)
    r = _IdentificationRound()
    gate_threshold = s_cfg.threat_relevance_threshold
    _apply_relevance_gate(r, sess, llm, sid, candidates, subsystems, asset_context, s_cfg,
                    queries, qvs, gate_threshold)

    if supersede:
        # Every unit the fan-out writes to, not just the asset: a stale subsystem row left
        # active from the previous round would double-count on the coverage grid.
        for unit in (ss, *grid_subsystem_ids):
            dal.supersede(sess, m.Identified_Threat, sid, unit)
    r.existing_identities = (dal.active_identified_threat_identities(sess, sid, ss)
                            if not supersede else {})

    held = _held_category_counts(sess, sid, ss, supersede, prior_threats)
    target = stride.allocate(max_threats, cats, existing=held)
    selected = _select_library_candidates(sid, r, target, max_threats)
    _admit_selected_candidates(r, sess, sid, tenant, ss, scenario_session, selected)
    _drop_prior_paraphrases(r, llm, sid, ss, scenario_session, tn, prior_threats)

    quantity_gap, coverage_missing, gap_need = _evaluate_coverage(r, target, max_threats)
    gap = _generate_gap_proposals(r, sess, llm, sid, ss, scenario_session, subsystems, asset_context,
                        cats, held, exclude, quantity_gap, coverage_missing, gap_need,
                        epoch, task_id, s_cfg, max_threats)
    _ground_and_admit_proposals(r, sess, llm, sid, tenant, ss, scenario_session, gap.proposals,
                    epoch, task_id)
    near_dupes = _drop_generated_duplicates(r, llm, sid, ss, scenario_session, tn,
                                            prior_threats)
    final_pairs, kept_ids, surplus = _finalize_stride_selection(r, sess, target, max_threats)
    backfilled, blocked = _backfill_to_count(r, sess, llm, sid, tenant, ss,
                                            scenario_session, tn, prior_threats, target,
                                            final_pairs, kept_ids, surplus, max_threats)

    r.rows = [row for row in r.rows if row["ThreatID"] in kept_ids]
    r.threats = [t for t in r.threats if t["threat_id"] in kept_ids]
    r.retrieved_summaries = [t for t in r.retrieved_summaries if t["threat_id"] in kept_ids]
    retrieved_ids = {t["threat_id"] for t in r.retrieved_summaries}
    delivered = len(r.threats)
    # WHICH threats were backfilled, with their gate scores — recorded, not just counted,
    # so a below-bar entry is identifiable from the audit row alone (the same
    # provenance-as-data standard as GroundingThresholdOrigin).
    backfilled_threats = [{"threat_id": t["threat_id"], "catalogue_id": t.get("catalogue_id"),
                        "relevance_score": t.get("relevance_score")}
                        for t in r.threats if t.get("backfill")]
    final_status = "COMPLETE" if delivered >= max_threats else "PARTIAL"
    if final_status == "PARTIAL":
        # A first-class outcome, not an error: the library, the backfill pool AND the LLM
        # together could not reach the count. Recorded in the audit; nothing is fabricated.
        log.warning("threats.partial_delivery", session_id=sid, subsystem=ss,
                    requested=max_threats, delivered=delivered, llm_failed=gap.llm_failed)

    fanout_rows = _build_fanout_rows(r, subsystems, grid_subsystem_ids, retrieved_ids)
    if r.rows:
        sess.execute(insert(m.Identified_Threat), r.rows + fanout_rows)
    if not dal.finish_stage(sess, sid, ss, SubsystemLevel.THREATS, StageStatus.COMPLETE, epoch, task_id):
        sess.rollback()
        log.warning("stage.claim_lost", session_id=sid, subsystem=ss, stage="THREATS", epoch=epoch)
        return [], None
    coverage_detail = _build_coverage_detail(sess, sid, ss, cats, grid_subsystem_ids)
    dal.append_audit(sess, AuditID=guid(), SessionID=sid, TenantID=tenant, EntityID=scenario_session["EntityID"],
                    Stage=WorkflowStage.THREAT_IDENTIFICATION, SubsystemID=ss,
                    EventType=AuditEventType.grounding_summary,
                    DetailJSON=json.dumps(_build_audit_payload(
                        r, status=final_status, requested=max_threats, delivered=delivered,
                        backfilled=backfilled, blocked=blocked,
                        backfilled_threats=backfilled_threats, quantity_gap=quantity_gap,
                        coverage_missing=coverage_missing, gate_threshold=gate_threshold,
                        gap=gap, gap_need=gap_need, near_dupes=near_dupes, target=target,
                        fanout_count=len(fanout_rows), coverage_detail=coverage_detail)))
    sess.commit()
    if r.dup_rows:
        # Deliberately OUTSIDE the transaction above, in its own try/except: this is an
        # audit-only table, and it must never be able to roll back or block the real
        # threats just committed — e.g. a deployment that hasn't re-run TSG_Core.sql yet
        # would otherwise lose a whole round's legitimate threats over a missing table.
        try:
            sess.execute(insert(m.Identified_Duplicate_Threat), r.dup_rows)
            sess.commit()
        except Exception:
            sess.rollback()
            log.warning("threats.duplicate_audit_insert_failed", session_id=sid,
                        subsystem=ss, exc_info=True)
    _send_live_update(sid, SSEEventType.stage_completed, ss, SubsystemLevel.THREATS, StageStatus.COMPLETE, epoch)
    log.info("stage.complete", session_id=sid, subsystem=ss, stage="THREATS", count=len(r.threats))
    return r.threats, gap.prov
