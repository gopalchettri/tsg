"""Create control-library mappings for generated scenario outputs — ORCHESTRATION ONLY.

The module grounds each scenario's own text (threat identity, narrative, asset and the systems
that scenario involves) against the control library and stores the matches the policy module
chooses — the LLM never proposes controls.

WHAT LIVES WHERE, and why the split exists. Every decision — what text a query is built from,
which ITOT labels a scenario may match, which matches become map rows and in what order, and what
must stop a write — is in ``control_relevance``, which takes plain data and touches no session,
client, clock or network. This module fetches, embeds, reranks, inserts and audits. The two used
to be one, and the cost is recorded in control_relevance's own docstring: two query builders
drifted apart, the ITOT filter was all-or-nothing, and a silent ``top_k`` slice threw away
controls that had cleared the cutoff without recording that it had.
"""
from __future__ import annotations

import json
import re
import time
from collections.abc import Callable, Mapping
from datetime import UTC, datetime, timedelta
from typing import Any, NamedTuple

from sqlalchemy import case, func, insert, or_, select, update
from sqlalchemy.exc import IntegrityError, PendingRollbackError
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.enums import (
    AuditEventType,
    ContentSource,
    ControlMappingExhaustionReason,
    ScenarioStatus,
    StageStatus,
    SubsystemLevel,
    WorkflowStage,
)
from app.core.logging import get_logger
from app.core.tracing import trace_step
from app.db import dal
from app.db import models as m
from app.db.dal import guid, now
from app.db.engine import db_session
from app.pipeline import control_relevance, embeddings, grounding, hybrid_search, threat_retrieval
from app.pipeline.llm import LLMClient, get_llm

log = get_logger(__name__)

#: How many Control_Library Domains may steer ONE scenario's ordering. A module constant, not a
#: setting: domain affinity is a sort key the policy module may only REORDER with — it can never
#: admit a control that failed the cutoff — so there is no operational decision to expose, and
#: `resolve_scenario_security_domains` already reads <=0 as "prefer nothing", which is exactly what
#: a failure of the embed below degrades to.
PREFERRED_DOMAIN_COUNT = 3

#: Embedding cache group for the DISTINCT Control_Library.Domain values. Its OWN group, never
#: `control_library`: embeddings.get_matrix keys the library matrix on a digest of the exact
#: "ControlName: Description" list (embeddings._CONTROL_TEXT), so mixing domain strings into that
#: group — or into that text — would invalidate and rebuild the whole library matrix every pass.
DOMAIN_EMBEDDING_GROUP = "control_domain"

def session_is_ot(sess: Session, subsystems: list[dict] | None, asset_context: dict) -> bool:
    """Is any of this session's asset/subsystem categories Operational Technology? Same
    code-first, then "(OT)"-in-name matching as _resolve_control_labels below — word-boundary-
    safe, unlike substring matching on free text ("OT" inside "PROTOTYPE"). A category with
    neither a matching code nor a recognizable name simply doesn't count; there is no free-text
    fallback (found 2026-08-27: the prior version of this check pattern-matched the asset's own
    free-text type instead of its already-available, DB-resolved ctm_scan_category)."""
    return "OT" in session_category_codes(sess, subsystems, asset_context)


def session_category_codes(sess: Session, subsystems: list[dict] | None, asset_context: dict) -> set[str]:
    """The session's ctm_scan_category CODES ('IT', 'OT', 'DATA_INFO', 'HUMAN_ROLE', 'FAC_LOC',
    'PHY_INFRA'), resolved from the asset's and every subsystem's category id. A row with no
    code but a recognizable "(OT)"/"(IT)" name still counts - same tolerance session_is_ot
    always had. Consumed by session_is_ot and by tasks._fetch_intel's prefer-order.

    Code and name marker are UNIONED, not tried in order: a row coded 'OT_LEGACY' but named
    "Operational Technology (OT)" is still OT, and this helper must not be narrower than the
    name-reading check it replaced. The marker is matched PARENTHESISED, never as a substring -
    "OT" also appears inside "PROTOTYPE"."""
    ids = threat_retrieval.session_category_ids(subsystems, asset_context)
    if not ids:
        return set()
    codes: set[str] = set()
    for code, name in sess.execute(
            select(m.ctm_scan_category.code, m.ctm_scan_category.name)
            .where(m.ctm_scan_category.id.in_(sorted(ids)))):
        cleaned = (code or "").strip().upper()
        if cleaned:
            codes.add(cleaned)
        codes.update(marker.upper() for marker in re.findall(r"\(([A-Za-z_]+)\)", name or ""))
    return codes


def _resolve_control_labels(sess: Session, asset_context: dict,
                            subsystems: list[dict] | None) -> list[str] | None:
    """The DATA-DRIVEN control-pool filter (G5): the ITOT labels matching ANY of the session's
    asset categories - the same union rule the threat filter uses. None = no filter.

    The rule itself now lives in grounding.resolve_asset_labels, shared with the technique
    reference so the two cannot drift into different answers for one session. Nothing is
    hardcoded to IT/OT: each session category is matched against the labels the control library
    ACTUALLY carries (grounding.control_itot_vocabulary), and if ANY category matches no label
    the filter is not applied at all - a silently narrowed pool is exactly the audited
    {Physical, IT}->IT-only defect this replaces."""
    return grounding.resolve_asset_labels(
        sess,
        threat_retrieval.session_category_ids(subsystems, asset_context),
        lambda: grounding.control_itot_vocabulary(sess),
        log_event="controls.category_without_vocabulary_no_filter")


def _min_score(sess: Session, llm: LLMClient | None, s) -> grounding.Threshold:
    """The score a grounded control must clear, WITH where that number came from.

    PRECEDENCE, and each branch carries its OWN origin so the audit row says which produced the
    number — the three collapse to the same handful of floats otherwise:

    1. ``Grounding_Calibration_Run.ControlMapTh`` — the newest successful CONTROL-MAP measurement
       FOR THIS EMBEDDING+RERANKER PAIR (``calibrated_for_control_mapping``). This is the only
       number ever MEASURED for the question this stage actually asks, so it out-votes a
       hand-written one;
    2. else ``control_map_min_score`` when the name is EXPLICITLY present in the environment
       (``env_pinned``) — the operator's bootstrap, and the only cutoff that exists before the
       first calibration has ever run;
    3. else the threat-grounding threshold, relabelled (see below).

    THE MEASUREMENT OUT-VOTES THE ENV FILE, by the owner's decision (2026-09-25), and the order
    above is the whole of that decision. The reasoning: the env value is a GUESS made before anyone
    measured this deployment, while branch 1 is the answer produced by scoring real scenarios
    against the real library. A first boot has no stored row, so ``.env`` is what runs; the moment a
    calibration stores a cutoff for this model pair, that value takes over — and because this
    function is called once per mapping PASS rather than once at boot (see READ ONCE PER PASS
    below), the switchover needs no restart and no redeploy.

    The consequence an operator must know: after a calibration, editing
    ``TSG_CONTROL_MAP_MIN_SCORE`` changes NOTHING for this model pair. To overrule a measurement,
    supersede it with another measurement, or clear ``ControlMapTh`` on the winning row. The audit
    row's ``effective_min_score_origin`` is what tells you which branch answered, so an operator who
    edits the env file and sees no change can see why in one field rather than guessing.

    KEYED ON THE MODEL PAIR, never "the latest row": ``grounding.latest_control_map_cutoff`` filters
    on ``(EmbeddingModel, RerankerModel)``, so a cutoff measured under a different pair is invisible
    here. That matters more than a missing measurement does — a number from another pair is not a
    cutoff for this one, and reading it would be worse than borrowing, because it would arrive
    labelled as measured.

    ABSENCE IS ``None``, NOT ZERO, and the branch tests exactly that. A measurement whose retrieval
    faulted ends ``no_signal`` with ``ControlMapTh`` left NULL, which is absence and must fall
    through to the borrowed threshold. A stored ``0.0`` is a different fact: the writer
    (``grounding.record_control_map_finished``) keys success on ``cutoff is not None``, so a measured
    zero WOULD be stored as a success, and a falsy test here would silently discard it and report a
    borrowed number as the cutoff in force. A cutoff of 0 admits every candidate, which is a loud,
    reviewable outcome under the origin ``calibrated_for_control_mapping`` — far better than the
    same behaviour arriving unexplained.

    READ ONCE PER PASS. Both callers (``_read_mapping_pass`` and ``_read_top_up_plan``) call this
    once, not per scenario, so step 2 is one small indexed SELECT per pass. It is deliberately NOT
    memoized, for the reason ``grounding.resolve_thresholds`` records at length: a process-level memo
    has no invalidation reachable from the admin route, so a re-measurement after curating the
    library would leave every warm worker on the superseded cutoff — which is precisely the "control
    matching picks it up with no restart" promise ``POST /v1/tsg/control-map/calibrate`` makes.

    ``llm`` may be ``None``. It is forwarded to ``grounding.resolve_thresholds``, which declares it
    ``LLMClient | None`` and documents it as "accepted but unused" — kept only so its many call
    sites need no edit. A caller that constructed a client just to fill it (the top-up did, via
    ``llm or get_llm()``) was paying for a parameter nothing reads.

    The origin matters more here than anywhere else. The fallback was calibrated
    label-vs-label, but this stage now queries with a scenario PARAGRAPH (library-first
    redesign) - a materially different score distribution. A cutoff too high drops every
    match, and an empty control list is documented as a healthy library gap, so the failure is
    invisible. Recording "this number was never measured for this question" alongside the
    number is what makes that reviewable afterwards."""
    measured = (grounding.latest_control_map_cutoff(sess, (s.embedding_model, s.reranker_model))
                if sess is not None else None)
    if measured is not None:
        return grounding.Threshold(measured, "calibrated_for_control_mapping")
    if "control_map_min_score" in s.model_fields_set:
        return grounding.Threshold(s.control_map_min_score, "env_pinned")
    borrowed = grounding.resolve_thresholds(sess, llm, s)
    # RE-LABELLED, not re-computed. resolve_thresholds answers for THREAT grounding, whose
    # calibration measured a short label against a short label; control mapping asks a different
    # question — a scenario PARAGRAPH against a control's name plus description — and its score
    # distribution is materially different. Returning that number is the documented fallback, but
    # returning it under the origin "calibrated" was a lie a reviewer could not see through: the
    # audit row then claimed a measurement that was never taken for this question. The number is
    # unchanged; only the provenance is now honest, which is the whole point of carrying an origin.
    # A control-specific measurement is what POST /v1/tsg/control-map/calibrate stores and branch 2
    # above now reads; scripts/measure_control_map_scores.py produces one to pin by hand instead.
    if borrowed.origin == "calibrated":
        return grounding.Threshold(borrowed.value, "borrowed_from_threat_grounding_uncalibrated")
    return borrowed


def _backfill_floor(cutoff: float, s) -> float:
    """The hard floor under backfill, as a FRACTION of the cutoff ACTUALLY in force.

    A RATIO, NOT AN ABSOLUTE, because the cutoff moves. `_min_score` resolves it from three
    sources, two of which config.py cannot see, so the old absolute 25.0 silently changed meaning
    every time that number moved: 42% of a cutoff of 60, 83% of a cutoff of 30, and at any cutoff
    at or below 25 the backfill band was EMPTY — `control_map_min_count` silently unreachable while
    looking configured. The boot validator that was supposed to catch that could only ever bound
    the EXPLICITLY-PINNED cutoff, so it has been deleted rather than left reading like a guarantee;
    `control_map_backfill_ratio`'s `gt=0.0, lt=1.0` bounds plus this function are the real guard,
    and they cover every source. A fraction strictly between 0 and 1 of any positive cutoff is
    strictly below that cutoff, so the band is non-empty by construction.

    THE DEPRECATED ABSOLUTE OVERRIDE is honoured only while it is genuinely below the cutoff in
    force. Obeying one that is not would reinstate the exact empty band this replaces — on the say
    of a setting whose author could not have known what the cutoff would resolve to — so it is
    logged and the ratio is used instead. Silently obeying it, or silently ignoring it, are both
    worse than saying so.

    A CUTOFF OF 0 (possible: a stored measurement of 0.0 is a success row — see `_min_score`) makes
    the floor 0 and the band [0, 0) empty. That is correct rather than a hole: rerank scores are
    0-100, so at a cutoff of 0 every candidate CLEARS the cutoff and there is no shortfall for
    backfill to fill at all. The permissiveness belongs to the cutoff and only `max_count` bounds
    it; no floor can or should undo a measured cutoff of zero, and the audit row names the origin.
    """
    ratio_floor = s.control_map_backfill_ratio * cutoff
    if "control_map_backfill_min_score" not in s.model_fields_set:
        return ratio_floor
    pinned = s.control_map_backfill_min_score
    if pinned < cutoff:
        return pinned
    log.warning("controls.backfill_floor_override_ignored", pinned=pinned, cutoff=cutoff,
                floor=round(ratio_floor, 2), ratio=s.control_map_backfill_ratio,
                note="TSG_CONTROL_MAP_BACKFILL_MIN_SCORE is at or above the cutoff actually in "
                    "force, which would leave the backfill band empty and control_map_min_count "
                    "unreachable. Using TSG_CONTROL_MAP_BACKFILL_RATIO instead — unset the "
                    "deprecated absolute, or lower it below the cutoff.")
    return ratio_floor


def _involved_system_names(scenario: dict) -> list[str]:
    """The supporting systems THIS scenario's narrative is actually about, by name.

    Reads the public `supporting_systems_involved` contract (schemas.SupportingSystemInvolved):
    each item's `supporting_system`. Model-authored, so every shape is tolerated — a non-list, a
    non-dict item or a missing key contributes nothing rather than raising three frames later.
    """
    involved = scenario.get("supporting_systems_involved")
    if not isinstance(involved, list):
        return []
    return [name for item in involved if isinstance(item, dict)
            if (name := grounding.ensure_text(item.get("supporting_system")).strip())]


def _retrieval_query(threat: Mapping[str, Any], scenario: dict, *, asset_name: Any,
                    asset_technology: Any, max_chars: int) -> str | None:
    """ONE scenario's control-retrieval query. Both passes build theirs here.

    `threat` is a row MAPPING (Row._mapping or dal.scenario_row's RowMapping) rather than a
    positional Row, so the generation pass and the remediation top-up can share this function
    even though their SELECTs differ — and so widening either SELECT can never silently shift a
    field onto the wrong argument, which is exactly what `for oid, _ in outputs` once did here.

    Library spelling leads for both type and name, the same preference the API uses for display:
    the curator's wording is what the control library was written against.
    """
    return control_relevance.build_control_retrieval_query(
        threat_category=threat.get("ThreatCategory"),
        threat_type=threat.get("LibraryThreatType") or threat.get("ThreatType"),
        threat_name=threat.get("LibraryThreatName") or threat.get("ThreatName"),
        threat_actors=grounding.stored_actors(threat.get("ThreatActorsJSON")),
        scenario_title=scenario.get("scenario_title"),
        scenario_statement=scenario.get("scenario_statement"),
        risk_statement=scenario.get("risk_statement"),
        asset_name=asset_name, asset_technology=asset_technology,
        involved_system_names=_involved_system_names(scenario), max_chars=max_chars)


class _SystemCategoryIndex(NamedTuple):
    """The session's scoped supporting systems, keyed BOTH ways, so a scenario can be joined by id.

    A scenario names the systems it involves in `supporting_systems_involved`, whose public
    contract (schemas.SupportingSystemInvolved) carries `supporting_system_id` AND
    `supporting_system`. The ITOT rule needs their ctm_scan_category ids. This used to join on the
    NAME alone, requiring an exact non-null string match against the session JSON — so a system
    renamed in onboarding after the session was scoped, or a name the model reworded, contributed
    no category at all and the scenario's ITOT context quietly narrowed to the asset's alone.

    Both maps rather than a query because context.py already stamped `id`, `name` and
    `asset_type_id` onto the session JSON; `by_system_id` is the authoritative join (the id is the
    onboarding_supporting_systems PK the session was scoped from) and `by_name` stays as the
    fallback for a scenario whose entry predates the id or omits it.
    """
    by_system_id: dict[int, int]
    by_name: dict[str, int]


def _system_category_index(subsystems: list[dict] | None) -> _SystemCategoryIndex:
    """Build `_SystemCategoryIndex` from the session's SubsystemsJSON. Tolerant of every shape:
    the blob is stored JSON, so a missing key or a non-int id simply does not contribute a door."""
    by_system_id: dict[int, int] = {}
    by_name: dict[str, int] = {}
    for sub in subsystems or []:
        if not isinstance(sub, dict) or sub.get("asset_type_id") is None:
            continue
        category_id = int(sub["asset_type_id"])
        if isinstance(sub.get("id"), int):
            by_system_id[sub["id"]] = category_id
        if name := grounding.ensure_text(sub.get("name")).strip():
            by_name[name] = category_id
    return _SystemCategoryIndex(by_system_id, by_name)


class _InvolvedSystemCategories(NamedTuple):
    """One scenario's involved systems resolved to category ids — AND the ones that could not be.

    `unresolved` is the whole point. A system that matches neither door contributes no category,
    which silently narrows the scenario's ITOT context to its asset's alone; recording the fact is
    what lets a reviewer tell that narrowing apart from a scenario that genuinely involves one
    system. Each entry is rendered as the scenario named it (`id=306` or the name), so the audit
    row says which system to go and look at.
    """
    category_ids: list[int]
    unresolved: tuple[str, ...]


def _involved_system_categories(scenario: dict,
                                index: _SystemCategoryIndex) -> _InvolvedSystemCategories:
    """Resolve `supporting_systems_involved` to category ids BY ID FIRST, then by name.

    The id is preferred because it is the only stable key: onboarding rows are renamed, and the
    scenario's `supporting_system` string is model-authored text that merely usually matches. A
    entry carrying neither a resolvable id nor a resolvable name lands in `unresolved` rather than
    being dropped, because "this scenario's ITOT context is missing a system" is a fact, not a
    non-event.
    """
    involved = scenario.get("supporting_systems_involved")
    if not isinstance(involved, list):
        return _InvolvedSystemCategories([], ())
    category_ids: list[int] = []
    unresolved: list[str] = []
    for item in involved:
        if not isinstance(item, dict):
            continue
        system_id = item.get("supporting_system_id")
        name = grounding.ensure_text(item.get("supporting_system")).strip()
        if isinstance(system_id, int) and system_id in index.by_system_id:
            category_ids.append(index.by_system_id[system_id])
        elif name in index.by_name:
            category_ids.append(index.by_name[name])
        elif isinstance(system_id, int) or name:
            unresolved.append(f"id={system_id}" if isinstance(system_id, int) else name)
    return _InvolvedSystemCategories(category_ids, tuple(sorted(set(unresolved))))


def _category_code_by_id(sess: Session, category_ids: set[int]) -> dict[int, tuple[Any, Any]]:
    """{ctm_scan_category id: (code, name)} for every id this pass will resolve — ONE query.

    Fetched once and reused across every scenario on purpose. The ITOT context is per scenario
    now, and resolving it per scenario would turn one small indexed SELECT into a round trip per
    output on a batch endpoint — the same N+1 the threat identity already rides `eligible_outputs`
    to avoid. Both columns are needed: the code is the primary match and the NAME carries the
    parenthesised "(CODE)" marker that is the second matching door.
    """
    if not category_ids:
        return {}
    return {row.id: (row.code, row.name) for row in sess.execute(
        select(m.ctm_scan_category.id, m.ctm_scan_category.code, m.ctm_scan_category.name)
        .where(m.ctm_scan_category.id.in_(sorted(category_ids))))}


class _ScenarioItotContext(NamedTuple):
    """One scenario's ITOT context, plus the involved systems that could not be resolved to one.

    The two travel together because the second is the provenance of the first: a context that
    looks narrow may be narrow because the scenario is narrow, or because a system it names did
    not resolve. Named rather than a 2-tuple for the reason MappingTally gives.
    """
    context: control_relevance.ItotApplicabilityContext
    unresolved_systems: tuple[str, ...]


def _itot_contexts(sess: Session, scenarios: dict[str, dict], asset_context: dict,
                subsystems: list[dict] | None) -> dict[str, _ScenarioItotContext]:
    """An ITOT applicability context PER SCENARIO, with the category lookup fetched once for all.

    Per scenario, not per session, and that is the point. A session is the union of everything
    scoped into it; a scenario is usually about a corner of it, so deriving from the union made an
    OT-only scenario rank the whole IT control pool as applicable. Each scenario's own asset plus
    the supporting systems IT names decide; `threat_retrieval.session_category_ids` is only the
    fallback for a scenario that names none (see
    control_relevance.resolve_scenario_itot_applicability, which records which happened).

    The scenario-to-system join is BY ID first (see `_involved_system_categories`), and a system
    that resolves through neither door is returned beside the context rather than dropped: it
    reaches `_relevance_detail` and the audit row, because a context narrowed by a lookup miss must
    not read like a context narrowed by a narrow scenario.

    Shared by the generation pass (many scenarios) and the remediation top-up (exactly one), so
    the two cannot drift into different answers for the same scenario.

    NEITHER the category lookup NOR the vocabulary is read until there is at least one category id
    to resolve — the same discipline `grounding.resolve_asset_labels` takes a vocabulary FACTORY
    for, and for the same measured reason: both of its callers built the vocabulary eagerly on
    sessions that had no categories to match at all, so the cheap path paid for a query it could
    not use.
    """
    index = _system_category_index(subsystems)
    session_ids = threat_retrieval.session_category_ids(subsystems, asset_context)
    raw_asset_category = (asset_context or {}).get("asset_type_id")
    asset_category_id = raw_asset_category if isinstance(raw_asset_category, int) else None
    involved = {scenario_id: _involved_system_categories(scenario, index)
                for scenario_id, scenario in scenarios.items()}
    for scenario_id, resolved in involved.items():
        if resolved.unresolved:
            log.warning("controls.involved_system_unresolved", scenario_id=str(scenario_id),
                        systems=list(resolved.unresolved))
    wanted = set(session_ids) | {cid for r in involved.values() for cid in r.category_ids}
    if asset_category_id is not None:
        wanted.add(asset_category_id)
    if not wanted:
        return {scenario_id: _ScenarioItotContext(
                    control_relevance.ItotApplicabilityContext(), resolved.unresolved)
                for scenario_id, resolved in involved.items()}
    code_by_id = _category_code_by_id(sess, wanted)
    vocabulary = grounding.control_itot_vocabulary(sess)
    return {scenario_id: _ScenarioItotContext(
                control_relevance.resolve_scenario_itot_applicability(
                    asset_category_id=asset_category_id,
                    involved_system_category_ids=resolved.category_ids,
                    session_category_ids=session_ids,
                    category_code_by_id=code_by_id, vocabulary=vocabulary),
                resolved.unresolved)
            for scenario_id, resolved in involved.items()}


class MappingTally(NamedTuple):
    """What one mapping pass did — the numbers the audit row and the log line both read.

    Built by `_tally` from the ControlSelection objects the policy module returned, so the audit
    cannot report a number the decision did not make. That drift is what this replaces: `inserted`
    and `dropped` were counted by hand in the loop while the `top_k` slice silently discarded
    controls that HAD cleared the cutoff, and nothing anywhere recorded that it had — a scenario
    with forty good controls and one with exactly five were indistinguishable afterwards.

    A NamedTuple rather than loose ints threaded through three functions: this module has
    already been bitten once by positional data (`for oid, _ in outputs` silently became a
    ValueError the moment the SELECT grew), and named fields make that class of slip impossible.
    """
    mapped: int
    cleared_cutoff: int
    backfilled: int
    capped: int
    itot_demoted: int
    dropped: int
    unanswered: int
    skipped: int
    conflicted: int
    conflict_outcome: str


def _tally(selections, *, unanswered: int, skipped: int,
        conflict: _InsertOutcome) -> MappingTally:
    """Fold the pass's ControlSelections into one tally — the ONLY place these numbers are made.

    `selections` must be the selections actually WRITTEN: a scenario whose insert lost a PK race
    was rolled back, so counting it here would report controls that are not in the table.

    `conflict` is the SAME `_InsertOutcome` `_settle_pass` derived `answered` from, which is what
    makes `conflicted`/`conflict_outcome` incapable of drifting from the decision they describe. An
    ABANDONED batch — the isolation retry clashing too — used to be invisible here: every scenario
    came back clashed, `selections` folded to nothing, and the audit row recorded every count as 0,
    byte-identical to a clean pass that reranked everything and matched nothing, which schemas.py
    documents as a genuine library gap. A separately-maintained counter would have been the same
    defect one step later, so the outcome rides in from the branch that produced it.
    """
    return MappingTally(
        mapped=sum(sel.mapped_count for sel in selections),
        cleared_cutoff=sum(sel.cleared_cutoff_count for sel in selections),
        backfilled=sum(sel.backfilled_count for sel in selections),
        capped=sum(sel.capped_count for sel in selections),
        itot_demoted=sum(sel.itot_demoted_count for sel in selections),
        dropped=sum(sel.dropped_below_cutoff_count for sel in selections),
        unanswered=unanswered, skipped=skipped,
        conflicted=len(conflict.clashed), conflict_outcome=conflict.outcome)


def _under_attempt_limit(attempts_col):
    """The control-mapping eligibility predicate — factored into ONE function so
    `eligible_outputs` and `sessions_awaiting_control_mapping` cannot drift apart the way their
    accepted/superseded predicate once did (see eligible_outputs' own docstring on that incident).

    HARD CUTOFF, by explicit owner instruction: once a row reaches control_map_max_attempts
    without a ControlsMappedAt stamp, it is excluded from every future sweep/pipeline mapping pass
    - permanently, not a backoff. It will not be retried again even if the underlying cause (e.g.
    an empty control library for its category) is later fixed; that requires a regenerate. A fresh
    row (ControlMapAttempts=0) is always eligible, exactly as before this limit existed - no
    behaviour change for the common case."""
    return attempts_col < get_settings().control_map_max_attempts


def _not_hand_written(source_column):
    """The provenance half of the eligibility predicate: a scenario is out of scope for mapping BY
    WHAT IT IS, not by what some writer stamped on it. Factored into ONE function for the reason
    `_under_attempt_limit` gives — `eligible_outputs` and `sessions_awaiting_control_mapping` both
    apply it and must not drift.

    Owner instruction, verbatim: "This is need to be done only for threat scenario generated by AI
    not for the manual threat scenario, if manual threat scenarios has the control count less than
    5 do not do anything." A person who writes a scenario chooses its controls, and their judgement
    IS the record — so no scored pass and no sweep may add to it, and a short list (1-4 chosen
    codes) is not a defect to be repaired. This is the most explicit constraint on the whole feature.

    THE ONE CASE THE INSTRUCTION DOES NOT COVER is a manual scenario saved with ZERO controls
    (owner decision D1, 2026-09-25): it is mapped, with the same matching an AI scenario gets, by the
    plan-launch top-up alone (`top_up_scenario_controls`, whose read phase applies the same reading
    of this column in Python and declines the moment the scenario carries any map row). Never by
    the scored pass and never by the sweep: this predicate is unchanged, so nothing that selects
    through it can see a manual row of any kind.

    WHY IT HAD TO BECOME ITS OWN GUARD. Until 2026-09 every manual scenario arrived WITH controls,
    so `ControlsMappedAt IS NOT NULL` and "has Threat_Scenario_Control_Map rows" were both true of
    it and either one alone kept it out. Then `mapped_controls` became optional ("a manual scenario
    without mapped_controls is saved with no controls, and the plan says so. Nothing is added,
    because top-up is for AI scenarios only"), and a control-less manual row genuinely has no map
    rows: the map-row guard stopped holding for a whole CLASS of scenario, leaving a mutable
    timestamp as the only thing between a person's scenario and a mapping pass. The save had to
    stamp ControlsMappedAt on a control-less row specifically to compensate, and said so in a
    comment. This column test removes that dependency: clear the stamp, delete every map row, and a
    hand-written scenario is still not selectable, because its provenance did not change.

    NULL IS NOT MANUAL, and that is why this is an `or_` and not a bare `!=`. ScenarioSource is
    nullable and NULL reads as "generated" everywhere else (`sessions.py::_scenario_source` returns
    `row.get("ScenarioSource") or "generated"`; error rows and every row written before the column
    existed carry NULL). In SQL `NULL != 'manual'` evaluates to NULL, which a WHERE clause treats
    as not-true — so a bare `!=` would silently drop every AI scenario with an unset source out of
    BOTH mapping selections, recreating precisely the permanent `controls: []` the retry sweep was
    built to end. tests/test_control_map_sweep.py seeds its scenarios with no ScenarioSource at
    all, so that mistake fails there loudly rather than in production.

    Deliberately the SAME reading of NULL that `_read_top_up_plan` applies in Python
    (`str(scn["ScenarioSource"] or "") == str(ContentSource.manual)`), so the guard on the scored
    path and the guard on the top-up path cannot disagree about one row. The one remaining way
    they could differ is CASE: SQL Server's default collation is case-insensitive, so a stored
    'MANUAL' would be excluded here and read as generated by the Python test. Both directions are
    safe here (this one keeps the row out; the top-up would need a second defect to write to a
    person's chosen list), and ContentSource exists precisely so that spelling cannot be stored —
    see its own docstring, which names this drift as the reason it is an enum.

    A plain column test, not an EXISTS: both callers run in the sweep's hot path, and this adds a
    residual predicate on a row the query already has in hand rather than a second row source.
    """
    return or_(source_column.is_(None), source_column != str(ContentSource.manual))


def eligible_outputs(sess: Session, session_id: str) -> list:
    """Outputs this session still owes controls, each row carrying its own threat identity.

    The WHOLE threat identity rides along on the SAME row as the scenario text — category, type,
    name, library spellings and the stored actors — because `_retrieval_query` needs all of it and
    a second lookup per output would be an N+1 on a batch endpoint. ThreatCategory and
    ThreatActorsJSON were added here rather than fetched per scenario for exactly that reason: the
    join is already running. OUTER join — an output whose scoped/threat chain is missing still maps
    on its narrative alone rather than being silently skipped.

    Read the columns BY NAME (`row.ScenarioID`, or `row._mapping` for a dict view). This SELECT has
    grown twice now, and a positional read of it has already cost this module one swallowed
    ValueError (see `_stamp_mapped_outputs`).

    THREE guards keep a hand-written scenario out, and exactly ONE of them holds for every manual
    scenario independently of anything a writer does later:

    * `_not_hand_written(ScenarioSource)` — the row's OWN provenance, never rewritten after the
      save. THE guard. It is what makes the owner's requirement structural rather than incidental.
    * `ControlsMappedAt IS NULL` — MUTABLE. The manual save stamps it, and any writer that cleared
      it (a reopened scenario, a repair script, a future regenerate path) would hand the row back.
    * `~already_mapped.exists()` — MUTABLE, and since 2026-09 VACUOUS for a whole class of manual
      scenario: `mapped_controls` is optional, so a manual row saved with no controls has no map
      rows and this guard never applied to it at all.

    This docstring used to claim "TWO INDEPENDENT guards ... no stamp, and no existing map rows".
    That was true while every manual scenario arrived with controls and stopped being true the day
    the payload made them optional, which left one mutable timestamp carrying the owner's most
    explicit requirement while the comment asserted a redundancy that no longer existed. An
    overstated guarantee in a comment this codebase's readers cite as evidence IS the defect, so
    the fix was to add the guard the claim described rather than to soften the claim.

    None of the three may be relaxed to accommodate another writer. The plan-launch top-up
    (`top_up_scenario_controls`) is the one other writer, and since D3 it MAY fill a scenario this
    SELECT still lists — an AI scenario whose `ControlsMappedAt` is NULL — in which case it stamps
    the row conditionally (`WHERE ControlsMappedAt IS NULL`, `_write_top_up`) and `_settle_pass`
    re-reads the stamp right before its own insert, so the two writers can never both map one
    scenario. A manual scenario with zero rows is filled by that top-up too, and by nothing that
    selects through here. Pinned by
    test_remediation_plans.py::test_no_mapping_pass_can_ever_select_a_manual_scenario, which drives
    BOTH kinds of manual scenario — one saved with the author's controls, one saved with none —
    clears one reason at a time and proves each remaining guard still holds on its own.
    """
    already_mapped = select(m.Threat_Scenario_Control_Map.ScenarioID).where(
        m.Threat_Scenario_Control_Map.ScenarioID == m.Threat_Scenario.ScenarioID)
    out_t, st_t, it_t = m.Threat_Scenario, m.Scoped_Threat, m.Identified_Threat
    # list(...): .all() returns a real list at runtime; the stubs declare Sequence.
    return list(sess.execute(
        select(out_t.ScenarioID, out_t.ScenarioJSON,
            it_t.ThreatName, it_t.ThreatType,
            it_t.LibraryThreatName, it_t.LibraryThreatType,
            it_t.ThreatCategory, it_t.ThreatActorsJSON)
        .select_from(out_t.__table__
                    .outerjoin(st_t, out_t.ScopedThreatID == st_t.ScopedThreatID)
                    .outerjoin(it_t, st_t.ThreatID == it_t.ThreatID))
        .where(out_t.SessionID == session_id,
            # Mirrors sessions_awaiting_control_mapping's predicate, and must: the sweep queues
            # a session, then THIS select decides what to map. Widening only the queue left an
            # accepted-but-superseded output queued forever and mapped never — the sweep
            # reported success while writing nothing.
            or_(dal.active(out_t.Superseded), out_t.Accepted == 1),
            out_t.Status == ScenarioStatus.complete,
            out_t.ControlsMappedAt.is_(None),
            _not_hand_written(out_t.ScenarioSource),
            _under_attempt_limit(out_t.ControlMapAttempts),
            ~already_mapped.exists())
    ).all())


class _ScenarioMappingPlan(NamedTuple):
    """Everything ONE scenario's selection needs, assembled before any model call.

    Named rather than a 4-tuple for the reason MappingTally gives: positional data has already
    cost this module a swallowed ValueError, and these travel together into the grounding batch and
    back out of it.

    `unresolved_systems` is carried, not discarded, so `_relevance_detail` can put it in the audit
    row — see `_involved_system_categories`.
    """
    scenario_id: str
    query: str
    itot_context: control_relevance.ItotApplicabilityContext
    unresolved_systems: tuple[str, ...]


def _plan_scenarios(sess: Session, outputs, scenario_session: dict, asset_context: dict,
                    subsystems: list[dict] | None, max_chars: int) -> list[_ScenarioMappingPlan]:
    """One query + one ITOT context per output, dropping the outputs with nothing to ask.

    An absent query is NOT a failure: a row with neither threat identity nor narrative (an error
    card whose chain is missing too) has nothing groundable in it. The caller counts the difference
    as `skipped` and stamps those rows, because "there was nothing to ask" is a definitive answer,
    not a retryable one.

    The asset context TRAILS the threat and the narrative inside the query, where the clip is most
    likely to bite — see build_control_retrieval_query. `asset_technology` is the asset's own
    declared type, the only technology fact the session-level context carries; per-system
    technology reaches the query through the involved systems' names instead.
    """
    scenarios = {row.ScenarioID: _blob(row.ScenarioJSON, {}, column="ScenarioJSON")
                for row in outputs}
    contexts = _itot_contexts(sess, scenarios, asset_context, subsystems)
    asset_name = (scenario_session or {}).get("AssetName")
    asset_technology = (asset_context or {}).get("asset_type")
    plans = []
    for row in outputs:
        query = _retrieval_query(row._mapping, scenarios[row.ScenarioID], asset_name=asset_name,
                                asset_technology=asset_technology, max_chars=max_chars)
        if query:
            resolved = contexts[row.ScenarioID]
            plans.append(_ScenarioMappingPlan(row.ScenarioID, query, resolved.context,
                                            resolved.unresolved_systems))
    return plans


def _prime_query_vectors(llm: LLMClient, plans: list[_ScenarioMappingPlan],
                        session_id: str) -> dict[str, list[float]]:
    """Cache each DISTINCT query's vector once; grounding still works if this warm-up fails.

    llm.embed chunks to the provider's per-request cap internally, and asserts each chunk came back
    aligned — so this zip cannot pair a text with another query's vector.
    """
    texts = list(dict.fromkeys(plan.query for plan in plans))
    try:
        return dict(zip(texts, llm.embed(texts, kind="query")))
    except Exception:
        log.warning("controls.query_prime_failed", session_id=session_id, exc_info=True)
        return {}


def _preferred_domains(llm: LLMClient, s, candidates: list[dict],
                    plans: list[_ScenarioMappingPlan],
                    query_vectors: dict[str, list[float]]) -> dict[str, frozenset[str]]:
    """{scenario id: the few control Domains its query is closest to} — ORDERING ONLY, FAIL-SAFE.

    The DISTINCT domains are embedded once per pass under DOMAIN_EMBEDDING_GROUP, never as part of
    the control text (see that constant for the cache-invalidation reason). Scored with the same
    cosine the shortlist uses, then cut by the policy module.

    ANY failure returns an EMPTY mapping and the pass continues unchanged: a library with no Domain
    column populated, an embed error, a query whose vector never primed. Domain affinity may only
    reorder controls that already cleared the cutoff, so losing it costs a tie-break and nothing
    else — which is why this logs a warning rather than raising, and why the broad except is
    deliberate.
    """
    try:
        domains = sorted({grounding.ensure_text(row.get("Domain")).strip()
                        for row in candidates} - {""})
        if not domains:
            return {}
        vectors = embeddings.get_vectors(llm, domains, model_id=s.embedding_model,
                                        group=DOMAIN_EMBEDDING_GROUP, kind="passage")
        scored_for = {query: [(name, hybrid_search.cosine(vector, vectors[name]))
                            for name in domains if name in vectors]
                    for query, vector in query_vectors.items()}
        return {plan.scenario_id: control_relevance.resolve_scenario_security_domains(
                    scored_for.get(plan.query, ()), PREFERRED_DOMAIN_COUNT)
                for plan in plans}
    except Exception:
        log.warning("controls.domain_affinity_failed", exc_info=True)
        return {}


def _ground_plans(llm: LLMClient, plans: list[_ScenarioMappingPlan],
                query_vectors: dict[str, list[float]], candidates: list[dict], s,
                session_id: str) -> list[grounding.ControlMatches]:
    """The one slow call — every query against the SAME candidate pool — TIMED.

    This is where control mapping actually spends its wall clock: a real run took 604s of a 724s
    pipeline here with NO instrumentation inside it, so "83% of the run" was one opaque block that
    could not be attributed to the shortlist, the library embed or the cross-encoder. perf_counter
    (not dal.now) because this is a DURATION: monotonic, immune to a clock step mid-run.

    queries x shortlist_k is the upper bound on cross-encoder pairs, and pairs — not queries alone
    — is what predicts cost. Reported beside the duration so a future tuning decision on
    control_map_shortlist_k comes from measurement rather than arithmetic.
    """
    flat = [(plan.query, query_vectors.get(plan.query)) for plan in plans]
    started = time.perf_counter()
    try:
        return grounding.ground_control_queries(llm, flat, candidates, s)
    finally:
        seconds = time.perf_counter() - started
        log.info("controls.grounding_timing", session_id=session_id, queries=len(plans),
                max_pairs=len(plans) * s.control_map_shortlist_k, candidates=len(candidates),
                shortlist_k=s.control_map_shortlist_k, seconds=round(seconds, 2),
                seconds_per_query=round(seconds / max(1, len(plans)), 2))


class _PassSelections(NamedTuple):
    """One pass's decided map rows per scenario, plus what could not be decided."""
    by_scenario: dict[str, control_relevance.ControlSelection]
    unanswered: int
    warnings: list[str]


def _select_pass(plans: list[_ScenarioMappingPlan], match_lists, candidates: list[dict], *,
                session_id: str, min_score: float, backfill_min_score: float, s,
                preferred_domains: dict[str, frozenset[str]],
                created_at: datetime) -> _PassSelections:
    """Turn each ANSWERED query into one scenario's map rows, validated before anything persists.

    A plan whose rerank item FAILED is counted as `unanswered` and left completely alone — no map
    rows, and crucially not selected, so the stamp skips it and the next mapping run picks it
    straight back up. That is a different fact from "we reranked and nothing matched", which is a
    finished answer (see grounding.ControlMatches.answered).

    `min_count` is a TARGET and `max_count` a runaway ceiling — the pair that replaced
    control_map_top_k, which was one number trying to say both and therefore capped every scenario
    at five while leaving no floor at all.

    validate_control_mapping RAISES on corruption on purpose: the caller maps inside a savepoint,
    so a ValueError rolls the mapping back and leaves the scenario unstamped for the retry sweep,
    whereas a warning would be logged and the wrong rows written anyway. Both of its optional
    facts are passed explicitly — omitting `itot_by_control_id` or `expected_count` silently skips
    two of its three checks and returns the same empty list as a verified-clean batch.
    """
    candidate_ids = [row["ControlLibraryID"] for row in candidates]
    itot_by_control_id = {row["ControlLibraryID"]: row.get("ITOT") for row in candidates}
    by_scenario: dict[str, control_relevance.ControlSelection] = {}
    warnings: list[str] = []
    unanswered = 0
    for plan, result in zip(plans, match_lists):
        if not result.answered:
            unanswered += 1
            continue
        selection = control_relevance.select_applicable_controls(
            scenario_id=plan.scenario_id, session_id=session_id, matches=result.matches,
            itot_context=plan.itot_context,
            preferred_domains=preferred_domains.get(plan.scenario_id, frozenset()),
            min_score=min_score, backfill_min_score=backfill_min_score,
            min_count=s.control_map_min_count, max_count=s.control_map_max_count,
            created_at=created_at)
        # PREFIXED WITH THE SCENARIO ID. One audit row covers the whole pass and its `warnings`
        # list is truncated at 20, so on a thirty-scenario batch "mapped 2 controls, fewer than the
        # 5 expected" named no scenario at all — the advisory a reviewer most needs to act on was
        # the one they could not attribute.
        warnings += [f"scenario {plan.scenario_id}: {warning}"
                    for warning in control_relevance.validate_control_mapping(
                        rows=selection.rows, candidate_ids=candidate_ids,
                        itot_context=plan.itot_context,
                        backfill_min_score=backfill_min_score,
                        itot_by_control_id=itot_by_control_id,
                        expected_count=s.control_map_min_count)]
        by_scenario[plan.scenario_id] = selection
    return _PassSelections(by_scenario, unanswered, warnings)


def _conflicting_scenario_ids(sess: Session, scenario_ids) -> set[str]:
    """Which of these scenarios ALREADY hold a map row — one SELECT, after a clash.

    A scenario with any existing row is not this pass's to map: `eligible_outputs` excludes it, so
    its presence means another writer got there between that SELECT and the insert. The whole
    scenario is dropped rather than its colliding rows alone, because a partial insert would leave
    MapRank with a hole and "MapRank 1 = best match" is a published contract.
    """
    cmap = m.Threat_Scenario_Control_Map
    return {str(row[0]) for row in sess.execute(
        select(cmap.ScenarioID).distinct().where(cmap.ScenarioID.in_(sorted(scenario_ids))))}


def _settled_since_read(sess: Session, scenario_ids) -> set[str]:
    """Which of these scenarios were STAMPED while this pass was out grounding — one SELECT.

    `eligible_outputs` selected them with `ControlsMappedAt IS NULL`, but the plan-launch top-up
    (`_write_top_up`) may map and stamp a NULL-stamp scenario in the minutes between that read and
    this pass's insert. A scenario stamped since then already holds the rows its plan was frozen
    from, so this pass must not add a second set on top of them: it is dropped from the insert, the
    stamp and the tally, exactly as a PK clash is. Checked BEFORE the insert rather than left to
    the PK because the top-up's rows and this pass's rarely coincide id for id — the clash would
    only fire on the overlap and the rest would go in as a double mapping.
    """
    if not scenario_ids:
        return set()
    out = m.Threat_Scenario
    return {str(row[0]) for row in sess.execute(
        select(out.ScenarioID).where(out.ScenarioID.in_(sorted(scenario_ids)),
                                     out.ControlsMappedAt.is_not(None)))}


class _InsertOutcome(NamedTuple):
    """Which scenarios lost their rows to a concurrent writer, AND WHICH BRANCH decided that.

    `outcome` is "clean" (the batch went in first time), "isolated" (one IntegrityError, the
    non-clashing scenarios were re-inserted, only the offenders lost their rows) or "abandoned"
    (the isolation retry clashed too, so NOTHING was written and every scenario stays unstamped).

    The branch is a first-class value because "abandoned" and "clean" produced identical audit rows:
    on abandonment every scenario is clashed, so nothing is folded into the tally and every count
    lands on 0 — which schemas.py documents as a genuine, curated library gap. The only trace was
    one log line, and a log line is not the durable record. See `_tally`.
    """
    clashed: set[str]
    outcome: str


def _insert_selected_rows(sess: Session, rows_by_scenario: dict[str, list[dict]]) -> _InsertOutcome:
    """Insert every scenario's map rows, and return the scenario ids that CLASHED plus the branch.

    THE BATCH IS THE FAST PATH, deliberately: one executemany for the whole pass is one round
    trip, and this is already the pipeline's longest step (604s of a 724s run) — inserting per
    scenario unconditionally would turn that into a round trip per output, a performance
    regression dressed as robustness.

    But one duplicate used to take the WHOLE pass down with it. The map PK is
    (ScenarioID, ControlLibraryID), so a single concurrent writer cost every OTHER scenario in the
    batch its controls, swallowed into one `controls.mapping_failed` WARNING. So the batch stays,
    and only an IntegrityError pays for isolation: roll back, ask which scenarios actually hold
    rows already, and re-insert the rest as ONE batch. The offender alone loses its rows and, being
    returned here, is the only one left unstamped for the sweep to pick up.

    Isolating by SELECT rather than by re-inserting scenario by scenario is not just cheaper (two
    round trips instead of N): a per-scenario retry needs a SAVEPOINT each, and under pysqlite
    releasing a savepoint commits the enclosing transaction outright — which would make
    `durable=False` writes survive the caller's rollback, the exact 2026-08-20 incident
    test_control_mapping_durable.py pins.

    The rollback discards nothing else: the lease commit immediately precedes the grounding call,
    so this insert is the first write of its transaction, and the stamps and the audit come after.
    """
    flat = [row for rows in rows_by_scenario.values() for row in rows]
    if not flat:
        return _InsertOutcome(set(), "clean")
    try:
        sess.execute(insert(m.Threat_Scenario_Control_Map), flat)
        return _InsertOutcome(set(), "clean")
    except IntegrityError:
        sess.rollback()
        log.warning("controls.map_batch_conflict_isolating", scenarios=len(rows_by_scenario))
    clashed = _conflicting_scenario_ids(sess, rows_by_scenario)
    retry = [row for scenario_id, rows in rows_by_scenario.items() if scenario_id not in clashed
            for row in rows]
    try:
        if retry:
            sess.execute(insert(m.Threat_Scenario_Control_Map), retry)
    except IntegrityError:
        # A writer racing us inside the isolation pass itself. Nothing is written and every
        # scenario stays unstamped, which is the queue's own retry — never a partial mapping.
        sess.rollback()
        log.warning("controls.map_batch_conflict_abandoned", scenarios=len(rows_by_scenario))
        return _InsertOutcome(set(rows_by_scenario), "abandoned")
    for scenario_id in sorted(clashed):
        log.warning("controls.map_row_conflict", scenario_id=str(scenario_id))
    return _InsertOutcome(clashed, "isolated")


def _record_control_map_attempts(sess: Session, outputs) -> list[str]:
    """Increment ControlMapAttempts for every output about to be attempted this pass, committed
    immediately - the same CAS-increment idiom claim_stage uses for
    Subsystem_Stage_State.AttemptCount. Committing here, before the savepoint a later exception
    can roll back, is what makes the counter reliable even when the rest of the pass crashes -
    that is exactly the case an attempt limit needs to count.

    Every output here is still fresh or on its LAST allowed attempt (control_map_max_attempts) -
    nothing excludes a row from the rest of map_controls this pass, so an output on its final try
    still gets a real chance to succeed before the cutoff takes effect for good.

    Returns the ids now at or past control_map_max_attempts - candidates for
    _log_if_still_exhausted, NOT yet a claim that any of them are still unmapped. Checking that
    here, before the attempt runs, would log "exhausted" on a row that goes on to succeed on this
    very last try - the caller re-checks once the pass has actually settled.
    """
    # BY NAME. This function's own docstring above forbids positional reads of `outputs`, and this
    # line was still doing one: `eligible_outputs` returns eight joined columns and has grown
    # twice, which already cost the module a swallowed ValueError (see _stamp_mapped_outputs).
    ids = [row.ScenarioID for row in outputs]
    sess.execute(update(m.Threat_Scenario)
                .where(m.Threat_Scenario.ScenarioID.in_(ids))
                .values(ControlMapAttempts=m.Threat_Scenario.ControlMapAttempts + 1))
    sess.commit()
    max_attempts = get_settings().control_map_max_attempts
    # list(...): same Sequence-vs-list stub narrowing as eligible_outputs above.
    return list(sess.execute(
        select(m.Threat_Scenario.ScenarioID)
        .where(m.Threat_Scenario.ScenarioID.in_(ids),
            m.Threat_Scenario.ControlMapAttempts >= max_attempts)
    ).scalars().all())


def _log_if_still_exhausted(sess: Session, session_id: str, over_budget_ids: list) -> None:
    """The other half of _record_control_map_attempts - called from map_controls' `finally`, so
    it runs exactly once no matter which of that function's several early returns (or its
    exception path) fired, on the pass's ACTUAL outcome rather than its attempt count alone.

    Logs the ids that are BOTH at/past the limit AND still ControlsMappedAt IS NULL once the pass
    is done - i.e. this WAS their last allowed attempt and it failed. Fires exactly once per
    scenario: once logged, `_under_attempt_limit` permanently excludes these ids from every future
    `eligible_outputs`/`sessions_awaiting_control_mapping` call, so there is no later retry left to
    log again - by explicit owner instruction, this is a stop, not a backoff.
    """
    if not over_budget_ids:
        return
    max_attempts = get_settings().control_map_max_attempts
    still_unmapped = sess.execute(
        select(m.Threat_Scenario.ScenarioID)
        .where(m.Threat_Scenario.ScenarioID.in_(over_budget_ids),
            m.Threat_Scenario.ControlsMappedAt.is_(None))
    ).scalars().all()
    if still_unmapped:
        log.error("controls.mapping_exhausted", session_id=session_id,
                scenario_ids=[str(sid) for sid in still_unmapped], attempts=max_attempts,
                reason=ControlMappingExhaustionReason.retry_budget_exhausted)


def _stamp_mapped_outputs(sess: Session, outputs, plans: list[_ScenarioMappingPlan],
                        answered: list[str]) -> None:
    """Timestamp the outputs we ACTUALLY ANSWERED, plus those with no groundable query.

    NOT the whole `outputs` list, which is what this used to be. The stamp is permanent (nothing
    anywhere clears it) and `ControlsMappedAt IS NULL` is the ONLY thing keeping an output
    eligible for a later run — so stamping an output whose rerank had merely FAILED converted one
    transient 429 into a permanent, unrecoverable, authoritative-looking "the control library has
    nothing for this threat". Leaving it NULL is the entire fix: the row stays in the queue and
    tsg.map_controls_sweep retries it.

    A scenario whose insert lost a PK race is deliberately NOT in `answered` either: its rows were
    rolled back, so stamping it would publish "mapped, nothing matched" over a scenario that has
    no rows at all.
    """
    groundable = {plan.scenario_id for plan in plans}
    # By name, not by position: these rows carry the joined threat columns too, and a positional
    # `for oid, _ in outputs` silently became a ValueError the moment the SELECT grew — swallowed
    # into "controls.mapping_failed", i.e. every output left unstamped and unmapped.
    to_stamp = answered + [row.ScenarioID for row in outputs
                        if row.ScenarioID not in groundable]
    if to_stamp:
        sess.execute(update(m.Threat_Scenario)
                    .where(m.Threat_Scenario.ScenarioID.in_(to_stamp))
                    .values(ControlsMappedAt=now()))


def _relevance_detail(plans: list[_ScenarioMappingPlan],
                    preferred_domains: dict[str, frozenset[str]]) -> dict:
    """The pass's per-scenario ITOT/domain facts, reduced to audit-shaped scalars.

    Unioned across the pass because the audit row IS the pass — this event has never been one row
    per scenario. `itot_incomplete` counts the scenarios narrowed on PARTIAL information (a
    category the control library carries no label for), and it is persisted rather than merely
    logged for the same reason find_threats persists `gate_failed`: a fail-open path that does not
    record how often it degraded leaves a degraded run indistinguishable from a clean one.

    `itot_context_source` is the set of "scenario"/"session"/"none" verdicts, which is what tells a
    reviewer that a mapping looking too wide inherited the whole session's categories because the
    scenario named no systems of its own.

    `unresolved_involved_systems` is the same discipline one level down: a scenario naming a system
    that resolves to no ctm_scan_category narrowed its own ITOT context to the asset's alone and
    recorded nothing at all, so the narrowing was indistinguishable from a narrow scenario.
    """
    return {"itot_labels": sorted({label for plan in plans for label in plan.itot_context.labels}),
            "itot_context_source": sorted({plan.itot_context.derived_from for plan in plans}),
            "itot_incomplete": sum(1 for plan in plans if not plan.itot_context.is_complete),
            "unresolved_involved_systems": sorted({system for plan in plans
                                                for system in plan.unresolved_systems}),
            "domain_affinity": sorted({name for names in preferred_domains.values()
                                    for name in names})}


def _record_control_mapping(sess: Session, scenario_session: dict, subsystem_id: int, queried: int,
                            tally: MappingTally, threshold: grounding.Threshold,
                            backfill_min_score: float,
                            pool_labels: list[str] | None, relevance: dict,
                            warnings: list[str]) -> None:
    """Persist what this pass DECIDED, then log the same numbers. The audit row is the only
    durable record.

    Every count comes from the MappingTally the ControlSelections were folded into, so the audit
    and the decision cannot disagree — and `capped_count` in particular is now visible at all,
    which it never was while the cap was a silent slice.

    ONE key per number, deliberately: the old row carried `mapped`/`dropped` alongside a separate
    hand-kept log line, and the way to keep two spellings of one number honest is not to have two.
    `itot_pool_labels` is the SQL pool filter (session-wide, all-or-nothing) and is NOT the same
    fact as `itot_labels`, which is the per-scenario ordering context — hence two names.

    Advisory warnings are capped in the row and counted in full: on a thirty-scenario batch the
    unabridged list is kilobytes of nvarchar for a fact `warning_count` already carries.
    """
    log_fields = {"outputs": queried, "mapped_count": tally.mapped,
                "cleared_cutoff_count": tally.cleared_cutoff,
                "backfilled_count": tally.backfilled, "capped_count": tally.capped,
                "itot_demoted_count": tally.itot_demoted,
                "dropped_below_cutoff_count": tally.dropped,
                "unanswered": tally.unanswered, "skipped": tally.skipped,
                # The PK race, as a durable fact rather than a log line. "abandoned" is the one
                # that mattered: it reports every count as 0, which is byte-identical to a healthy
                # pass over an empty library unless the outcome itself is recorded.
                "conflicted_count": tally.conflicted,
                "conflict_outcome": tally.conflict_outcome,
                **relevance,
                "itot_pool_labels": pool_labels or [],
                "itot_filter_applied": bool(pool_labels),
                # WHERE the cutoff came from. Without it a stored 75.0 cannot be told apart from a
                # measured one, and "static_default" means it was tuned for a different model pair
                # AND a different question.
                "effective_min_score": threshold.value,
                "effective_min_score_origin": threshold.origin,
                # The floor is a FRACTION of the cutoff above, so the absolute it resolved to is a
                # derived number a reviewer cannot reconstruct from the settings alone — a stored
                # measurement moves the cutoff and the floor with it, with no config change.
                "effective_backfill_min_score": round(backfill_min_score, 4),
                "warning_count": len(warnings)}
    dal.append_audit(sess, AuditID=guid(), SessionID=scenario_session["SessionID"], EntityID=scenario_session["EntityID"],
                    Stage=WorkflowStage.SCENARIO_GENERATION, SubsystemID=subsystem_id,
                    EventType=AuditEventType.controls_mapped,
                    DetailJSON=json.dumps({**log_fields, "warnings": warnings[:20]}))
    log.info("controls.mapped", session_id=scenario_session["SessionID"],
            warnings=warnings[:5], **log_fields)


def _settle_pass(sess: Session, scenario_session: dict, subsystem_id: int, outputs,
                plans: list[_ScenarioMappingPlan], selected: _PassSelections, *,
                threshold: grounding.Threshold, backfill_min_score: float,
                pool_labels: list[str] | None,
                preferred_domains: dict[str, frozenset[str]], skipped: int) -> None:
    """The whole epilogue: write the rows, stamp what was answered, record the pass once.

    Kept together because the three are one decision seen from three sides, and separating them is
    how they drifted before: a scenario whose insert lost a PK race must be absent from the stamp
    AND from the tally, or the audit reports controls that are not in the table and
    `ControlsMappedAt` retires a scenario that has no rows.

    A scenario the plan-launch top-up settled meanwhile is dropped the same way, and for the same
    reason — see `_settled_since_read`.
    """
    settled = _settled_since_read(sess, selected.by_scenario)
    if settled:
        log.warning("controls.settled_elsewhere", session_id=scenario_session.get("SessionID"),
                    scenario_ids=sorted(settled))
    conflict = _insert_selected_rows(
        sess, {scenario_id: selection.rows
            for scenario_id, selection in selected.by_scenario.items()
            if selection.rows and scenario_id not in settled})
    answered = [scenario_id for scenario_id in selected.by_scenario
                if scenario_id not in conflict.clashed and scenario_id not in settled]
    _stamp_mapped_outputs(sess, outputs, plans, answered)
    if selected.unanswered:
        # Loud, attributable and joined to the session — unlike llm.rerank_many's
        # `rerank_item_failed`, which logs an anonymous batch index that joins to nothing.
        log.warning("controls.unanswered_left_for_retry",
                    session_id=scenario_session.get("SessionID"),
                    unanswered=selected.unanswered, of=len(plans))
    _record_control_mapping(
        sess, scenario_session, subsystem_id, len(plans),
        _tally([selected.by_scenario[scenario_id] for scenario_id in answered],
            unanswered=selected.unanswered, skipped=skipped, conflict=conflict),
        threshold, backfill_min_score, pool_labels,
        _relevance_detail(plans, preferred_domains), selected.warnings)


def map_controls(sess: Session, scenario_session: dict, asset_context: dict,
                subsystems: list[dict] | None, llm: LLMClient, subsystem_id: int,
                task_id: str, epoch: int, *, durable: bool) -> None:
    """Step-4 control mapping, timed. Delegates to `_map_controls_once` — see its docstring.

    The timing lives in this wrapper rather than inside the body ON PURPOSE: the body has five
    early returns and a broad exception handler, so measuring AROUND the call is the only way one
    measurement covers every exit path, and `finally` guarantees the number is recorded even when
    the pass bails out early.

    perf_counter, not dal.now: this is a DURATION — monotonic, immune to a clock step mid-run —
    the same reasoning already written above the grounding call inside. The SAME value feeds both
    the trace record and the database, so those two can never disagree.

    This is the pipeline's longest step (a real run spent 604s of 724s here) and had no
    instrumentation at all before this.
    """
    sid = scenario_session["SessionID"]
    _t0 = time.perf_counter()
    with trace_step("CONTROL MAPPING", sid, subsystem=subsystem_id, epoch=epoch,
                    durable=durable) as _t:
        try:
            _map_controls_once(sess, scenario_session, asset_context, subsystems, llm,
                            subsystem_id, task_id, epoch, durable=durable)
        finally:
            seconds = time.perf_counter() - _t0
            _t.result(seconds=round(seconds, 2))
            try:
                try:
                    # Cumulative: this pass may be one of several sweep ticks, so the session's
                    # total is the sum of the work, not a span across the waiting in between.
                    dal.accumulate_control_map_seconds(sess, sid, seconds)
                except PendingRollbackError:
                    # The pass left `sess` needing a rollback - a failed flush or an invalidated
                    # connection escaped the body's own handler (its begin_nested runs outside
                    # that try, its finally issues a SELECT, and a BaseException such as a gevent
                    # Timeout bypasses `except Exception` entirely). Whatever was pending is
                    # already unrecoverable, so rolling back discards nothing; the accumulate is
                    # a standalone atomic UPDATE and is safe to issue once more.
                    sess.rollback()
                    dal.accumulate_control_map_seconds(sess, sid, seconds)
                if durable:
                    sess.commit()
            # Same posture as the body: telemetry must never fail the pass it is measuring.
            # seconds= is the size of the hole: the column is cumulative, so a lost pass
            # under-reports the session forever with no other trace of it.
            except Exception:
                log.warning("controls.timing_write_failed", session_id=sid,
                            seconds=round(seconds, 2), exc_info=True)


class _MappingPassInputs(NamedTuple):
    """Everything one mapping pass's slow half needs, read before a single model call is made.

    The pass used to be one 47-code-line function, over this repo's ~40-line limit, and the three
    responsibilities it braided are what the limit exists to keep apart: the transaction/attempt
    scaffolding (`_map_controls_once`), the reads and per-scenario planning (`_read_mapping_pass`),
    and the grounding plus the epilogue (`_ground_and_settle_pass`). This value is the seam.
    """
    settings: Any
    outputs: list
    plans: list[_ScenarioMappingPlan]
    pool_labels: list[str] | None
    candidates: list[dict]
    threshold: grounding.Threshold
    backfill_min_score: float
    skipped: int


def _read_mapping_pass(sess: Session, scenario_session: dict, asset_context: dict,
                    subsystems: list[dict] | None, outputs, llm: LLMClient, subsystem_id: int, *,
                    durable: bool) -> _MappingPassInputs | None:
    """The pass's READS: the pool filter, the candidate pool, one plan per output, the cutoff.

    ``None`` means this pass is over before any model call — either the pool is empty (nothing to
    match against, nothing stamped, the row stays queued for the sweep) or no output had anything
    groundable to ask.

    THE NOTHING-GROUNDABLE PATH NOW WRITES ITS AUDIT ROW. It used to stamp the outputs and return
    BEFORE `_settle_pass`, so the one durable record of the pass was missing exactly when a reviewer
    most needs it: a scenario permanently stamped "mapped" with zero controls and no row anywhere
    saying the reason was an empty query rather than an empty library. It settles through the same
    `_settle_pass` as every other path, with an empty selection — which also means the stamp, the
    (empty) insert and the audit row stay the one decision they were before.
    """
    s = get_settings()
    sid = scenario_session["SessionID"]
    pool_labels = _resolve_control_labels(sess, asset_context, subsystems)
    # ONCE per pass, and UNFILTERED by scenario on purpose: embeddings.get_matrix caches the
    # library matrix under a digest of this exact text list, so a per-scenario pool would
    # rebuild (and evict) the whole matrix every scenario. ITOT now steers ORDERING inside
    # select_applicable_controls, which is why the pool no longer needs narrowing per scenario.
    candidates = grounding.get_control_candidates(sess, pool_labels)
    if not candidates:
        log.warning("controls.no_candidates", session_id=sid, itot_labels=pool_labels)
        return None
    plans = _plan_scenarios(sess, outputs, scenario_session, asset_context, subsystems,
                            s.max_embed_chars)
    skipped = len(outputs) - len(plans)
    threshold = _min_score(sess, llm, s)
    # Resolved HERE, beside the cutoff it is a fraction of, and threaded from this one value: the
    # floor and the cutoff are one decision, and a floor read separately from the setting is how it
    # came to mean something different from what its author intended (see `_backfill_floor`).
    backfill_min_score = _backfill_floor(threshold.value, s)
    if not plans:
        _settle_pass(sess, scenario_session, subsystem_id, outputs, plans,
                    _PassSelections({}, 0, []), threshold=threshold,
                    backfill_min_score=backfill_min_score, pool_labels=pool_labels,
                    preferred_domains={}, skipped=skipped)
        if durable:
            sess.commit()
        log.warning("controls.nothing_groundable", session_id=sid, skipped=skipped)
        return None
    return _MappingPassInputs(s, outputs, plans, pool_labels, candidates, threshold,
                            backfill_min_score, skipped)


def _ground_and_settle_pass(sess: Session, scenario_session: dict, subsystem_id: int,
                        llm: LLMClient, task_id: str, epoch: int, prepared: _MappingPassInputs, *,
                        durable: bool) -> None:
    """The slow half: prime, re-check the lease, ground, decide, settle.

    The lease is re-checked HERE, after the reads and immediately before the commit that ends the
    lease transaction, because everything past that commit is minutes of embed + rerank on a
    subsystem another writer may have taken. Losing it returns without stamping, which leaves every
    output in the queue for `sessions_awaiting_control_mapping` — see that function's docstring for
    why a queue with no consumer made "left for retry" a lie.
    """
    s, plans = prepared.settings, prepared.plans
    sid, ss = scenario_session["SessionID"], subsystem_id
    query_vectors = _prime_query_vectors(llm, plans, sid)
    if not (dal.renew_lease(sess, sid, ss, SubsystemLevel.SCENARIOS, epoch, task_id)
            or dal.stage_settled_at_epoch(sess, sid, ss, SubsystemLevel.SCENARIOS, epoch)):
        log.warning("controls.lease_lost", session_id=sid)
        return
    sess.commit()  # End the lease transaction before the slow grounding call.
    domains = _preferred_domains(llm, s, prepared.candidates, plans, query_vectors)
    match_lists = _ground_plans(llm, plans, query_vectors, prepared.candidates, s, sid)
    selected = _select_pass(plans, match_lists, prepared.candidates, session_id=sid,
                            min_score=prepared.threshold.value,
                            backfill_min_score=prepared.backfill_min_score, s=s,
                            preferred_domains=domains, created_at=now())
    _settle_pass(sess, scenario_session, subsystem_id, prepared.outputs, plans, selected,
                threshold=prepared.threshold, backfill_min_score=prepared.backfill_min_score,
                pool_labels=prepared.pool_labels, preferred_domains=domains,
                skipped=prepared.skipped)
    if durable:
        sess.commit()


def _map_controls_once(sess: Session, scenario_session: dict, asset_context: dict,
                subsystems: list[dict] | None, llm: LLMClient, subsystem_id: int,
                task_id: str, epoch: int, *, durable: bool = False) -> None:
    """Map applicable library controls onto every active, complete output this session still owes.

    ORCHESTRATION ONLY: reads the outputs with a null ``ControlsMappedAt``, no existing map rows
    and no hand-written provenance (``eligible_outputs`` owns all three guards and documents which
    of them is the independent one), builds one retrieval query and one ITOT context per scenario,
    fetches the candidate pool
    ONCE, grounds every query against that same pool via the hybrid shortlist + reranker, and asks
    ``control_relevance`` which matches become rows and in what order. It timestamps every output
    it answered, plus those with nothing groundable to ask. A mapping error is logged without
    failing scenario generation. With ``durable=True``, mapping writes are committed before this
    function returns.

    SUPERSEDED: the old body sliced each scenario to ``control_map_top_k`` with no floor, which is
    now ``control_map_min_count`` (a target) and ``control_map_max_count`` (a ceiling), with
    ``capped_count`` recording what the ceiling dropped.

    FIXED HERE TOO: the grounding-timing log used to sit OUTSIDE the ``if per_output`` block and
    read a variable only that block assigned, so a pass where nothing was groundable raised
    NameError into the handler below — rolled back, logged as ``controls.mapping_failed``, and left
    those outputs unstamped to be re-attempted until the attempt limit retired them. The timing now
    lives with the call it measures (``_ground_plans``) and the no-query path returns before it.

    WHAT IS LEFT HERE is only the scaffolding the savepoint and the attempt budget need: the reads
    are ``_read_mapping_pass`` and the slow half is ``_ground_and_settle_pass``. The body used to
    hold all three at 47 code lines, past this repo's ~40-line limit, and the three are exactly the
    responsibilities that limit separates — a transaction posture, a set of reads, and a model call
    with an epilogue. The savepoint, the broad ``except`` and the ``finally`` stay together because
    each of them has to cover every exit path of the other two.
    """
    # A savepoint prevents mapping errors from rolling back scenario writes.
    sp = sess.begin_nested()
    # Bound before try/except so `finally` always finds it, however this pass exits.
    over_budget_ids: list = []
    try:
        outputs = eligible_outputs(sess, scenario_session["SessionID"])
        if not outputs:
            return
        # BEFORE the savepoint-rollbackable work and committed by itself, which is why it stays
        # here rather than inside `_read_mapping_pass`: the `finally` below pairs with it.
        over_budget_ids = _record_control_map_attempts(sess, outputs)
        prepared = _read_mapping_pass(sess, scenario_session, asset_context, subsystems, outputs,
                                    llm, subsystem_id, durable=durable)
        if prepared is not None:
            _ground_and_settle_pass(sess, scenario_session, subsystem_id, llm, task_id, epoch,
                                    prepared, durable=durable)
    except Exception:
        # Roll back mapping changes and allow scenario generation to finish.
        (sp.rollback() if sp.is_active else sess.rollback())
        log.warning("controls.mapping_failed", session_id=scenario_session.get("SessionID"), exc_info=True)
    finally:
        # Close the savepoint after normal returns and early returns.
        if sp.is_active:
            sp.commit()
        # ONE place, covering every exit path (normal completion, every early return above, and
        # the exception handler) - the pass has now genuinely settled, so this reflects the ACTUAL
        # outcome instead of firing on a backed-off retry that goes on to succeed within this same
        # pass (see _log_if_still_exhausted's own docstring).
        _log_if_still_exhausted(sess, str(scenario_session["SessionID"]), over_budget_ids)


def _blob(raw: str | None, default, *, column: str):
    """A stored JSON column, or `default` when it is empty, unparseable or the wrong shape.

    DEGRADING IS THE BEHAVIOUR, SILENCE WAS THE DEFECT. Three different session/scenario blobs
    (`ScenarioJSON`, `AssetContextJSON`, `SubsystemsJSON`) route through here, and a corrupt one
    quietly became `{}`/`[]`: the ITOT context then narrowed to nothing, the query lost the
    scenario's narrative, and every downstream number looked like an honest thin answer. The
    default still comes back — a whole pass must not fail on one bad row — but `column` is
    required so the log line names WHICH blob, which is the only thing that makes the degrade
    reviewable afterwards.
    """
    try:
        parsed = json.loads(raw) if raw else default
    except ValueError:
        log.warning("controls.blob_unparseable", column=column)
        return default
    if not isinstance(parsed, type(default)):
        log.warning("controls.blob_wrong_shape", column=column,
                    got=type(parsed).__name__, expected=type(default).__name__)
        return default
    return parsed


#: The cutoff/floor that admits EVERY candidate, for the ordering-only call in
#: `_merged_control_ranks`. Nothing there may be dropped: every row it sees either already exists in
#: the map table or is about to, so the real cutoff has already been applied by `_select_top_up`.
_ADMIT_EVERYTHING = float("-inf")


def _unscored_order_score(map_rank: int) -> float:
    """Where an EXISTING map row whose Score is NULL sorts in the one ordering rule.

    Score is documented 0-100 (models.Threat_Scenario_Control_Map.Score), so any negative value
    sorts an unscored row behind every scored one — which is the property that matters: legacy rows,
    and the person-chosen rows of manual scenarios, carry NULL because their order is the person's
    own choice, and a top-up must never lift one above a control that was actually measured. (A row
    TSG maps onto a control-less manual scenario at plan launch is scored like any AI row.)

    Subtracting the row's OWN MapRank rather than returning one flat sentinel keeps the unscored
    rows in the sequence they already had. A single sentinel would tie them all and the ordering
    rule would fall through to its id tie-break, silently re-shuffling rows nothing asked to move.
    """
    return -1.0 - max(0, map_rank)


class _ExistingControl(NamedTuple):
    """One map row the scenario ALREADY carries, reduced to what the ordering rule reads.

    ITOT and Domain ride along from Control_Library because the top-up now re-orders the WHOLE
    scenario through `select_applicable_controls`, and that rule reads all three facts. Reading
    them here costs nothing: the join to Control_Library was already running for IsActive/IsDeleted.
    """
    control_library_id: Any
    map_rank: int
    score: float
    itot: Any
    domain: Any
    is_live: bool


class _TopUpPlan(NamedTuple):
    """Everything the remediation top-up needs from the database, read in ONE short transaction.

    A single value rather than nine locals precisely so the three phases stay separable: the read
    transaction closes before the embed + rerank round trips begin, and nothing in the grounding or
    write phase can reach back into a session that is gone.

    `existing` REPLACES the old `next_rank`/`taken` pair. Appending after the highest existing rank
    and then re-deriving every rank from Score alone is the defect this carries the facts to fix —
    see `_merged_control_ranks`.

    `need` is the shortfall under the floor and stays for the audit and the log; `min_count` /
    `max_count` are what the selection is actually sized by (see `_read_top_up_plan`). `stamp`
    says the scenario's `ControlsMappedAt` was NULL at read time, so a write must claim it.
    """
    scenario_id: str
    session_id: str
    scenario_source: str
    query: str
    need: int
    min_count: int
    max_count: int
    stamp: bool
    existing: tuple[_ExistingControl, ...]
    pool: list[dict]
    pool_widened: bool
    itot_context: control_relevance.ItotApplicabilityContext
    unresolved_systems: tuple[str, ...]
    min_score: grounding.Threshold
    backfill_min_score: float
    audit_columns: dict


def _top_up_refused(sess: Session, session_id: str, scenario_id: str, scn, *,
                    first_generation: bool = True) -> bool:
    """The states this path must decline — no grounding is spent on a request about to 4xx.

    Only the states the ROUTE refuses live here: a missing or unaccepted scenario (404/409), and on
    a first generation an active plan (409). A regenerate has an active plan by definition, so that
    clause is skipped for it. What the top-up declines on its OWN account — a person's chosen list,
    a regenerate of a scenario that already has live rows — is decided in `_read_top_up_plan`, which
    has the map rows in hand.

    `ControlsMappedAt` NULL is NO LONGER a refusal (decision D3, 2026-09-25). It used to be, because
    writing rows without the stamp tripped both scored-mapping guards and retired the scenario from
    the scored pass for good. `_write_top_up` now claims the stamp in the same transaction as its
    rows, conditionally, so a NULL-stamp scenario is mapped on the spot at plan launch — and if the
    scored pass settles it first the top-up's write rolls back instead of doubling it.
    """
    return (scn is None or scn["Accepted"] != 1
            or (first_generation
                and dal.active_plan_row(sess, session_id, scenario_id) is not None))


def _existing_map_rows(sess: Session, scenario_id) -> tuple[_ExistingControl, ...]:
    """Every map row this scenario ALREADY carries, with the facts the ordering rule reads. ONE query.

    EVERY row, not just the live ones: the map PK covers retired library rows too and every row in
    the table needs a rank, so the merge has to see them all. `is_live` is what the FLOOR counts —
    a retired control is not something the plan will show — and keeping both facts on one row is why
    this is a single select rather than two.

    Score, ITOT and Domain ride along because `_merged_control_ranks` runs the one ordering rule over
    these rows: three more columns on a join that was already running for IsActive/IsDeleted.
    """
    cmap, lib = m.Threat_Scenario_Control_Map, m.Control_Library
    rows = sess.execute(
        select(cmap.ControlLibraryID, cmap.MapRank, cmap.Score,
            lib.IsActive, lib.IsDeleted, lib.ITOT, lib.Domain)
        .outerjoin(lib, lib.ControlLibraryID == cmap.ControlLibraryID)
        .where(cmap.ScenarioID == scenario_id)).all()
    return tuple(_ExistingControl(
                    control_library_id=r.ControlLibraryID, map_rank=r.MapRank or 0,
                    score=(_unscored_order_score(r.MapRank or 0) if r.Score is None
                        else float(r.Score)),
                    itot=r.ITOT, domain=r.Domain,
                    is_live=bool(r.IsActive and not r.IsDeleted))
                for r in rows)


def _top_up_candidate_pool(sess: Session, asset_context: dict, subsystems: list[dict] | None, *,
                        taken: set, need: int,
                        scenario_id: str) -> tuple[list[dict[str, Any]], bool]:
    """The pool to ground against, and whether ITOT discipline had to be dropped to fill the floor.

    UNFILTERED by `taken`, on purpose: embeddings.get_matrix caches the library matrix under a digest
    of this exact list, so passing the pipeline's own list hits its cache instead of rebuilding (and
    evicting) one per scenario. The already-mapped ids are excluded from the MATCHES instead, which
    costs the cache nothing.

    When the asset-category filter leaves fewer than `need` usable candidates the pool widens to the
    whole library — "nearest possible" beats "fewer than asked" — and the second return value says
    so. That flag is the fix for a fail-open that recorded nothing: widening drops the very ITOT
    discipline the label filter exists to enforce, and a pool that was widened was indistinguishable
    afterwards from one that never needed to be.
    """
    labels = _resolve_control_labels(sess, asset_context, subsystems)
    pool = grounding.get_control_candidates(sess, labels)
    if not (labels and sum(c["ControlLibraryID"] not in taken for c in pool) < need):
        return pool, False
    log.warning("controls.top_up_pool_widened", scenario_id=scenario_id, need=need,
                itot_labels=labels)
    return grounding.get_control_candidates(sess, None), True


def _read_top_up_plan(sess: Session, session_id: str, scenario_id: str, s,
                    llm: LLMClient | None, *, first_generation: bool = True) -> _TopUpPlan | None:
    """Phase one: the gates, the floor arithmetic, the candidate pool and the query. None = decline.

    `control_map_min_count`, NOT the deprecated `remediation_control_min_count`: this is the same
    floor the mapping pass now applies, and the old env spelling still feeds the new setting, so an
    operator who pinned it keeps their number.

    THE TWO DECLINES THAT ARE THIS PATH'S OWN, both read off the map rows:

    * A MANUAL scenario with ANY map row — live or retired — is a person's chosen list and is
      never added to (owner instruction quoted in `_not_hand_written`: 1-4 chosen codes are not a
      defect). A manual scenario with NO rows is the one D1 case this path maps, with the same
      matching an AI scenario gets. NULL is read as generated here exactly as `_not_hand_written`
      reads it in SQL, so the two paths cannot disagree about one row.
    * A REGENERATE (`first_generation=False`) fills only a scenario with NO live rows (decision
      D2): a failed first fill-up can be repaired by regenerating, but a scenario that already has
      controls is never changed by writing its plan again.

    FILL SIZE. A scenario with no rows at all is sized the way the scored pass sizes one: at least
    the floor, every control above the cutoff, never past `control_map_max_count` (a safety cap,
    not a target). A scenario that already has rows is only topped up to the floor — `need` for
    both bounds, as before — because a remediation request is not the place to grow a list that
    was already sized once.

    THE EXISTING MAP ROWS ARE READ IN FULL — Score, ITOT and Domain, not just the id and the rank.
    They are what `_merged_control_ranks` runs the one ordering rule over, so the top-up orders the
    whole scenario instead of appending and then re-deriving rank from Score alone. Three more
    columns on a join that was already running for IsActive/IsDeleted.

    NOT FAIL-OPEN ITSELF: every read here can raise (a pyodbc timeout on the full Control_Library
    SELECT most plausibly) and the fail-open lives in `top_up_scenario_controls`, which wraps this
    call. It used to wrap only the two later phases, so a timeout in THIS one escaped into the HTTP
    handler and 500'd POST /v1/remediation-plans instead of planning from the controls already
    mapped — the identical failure one phase later logged and returned 0.
    """
    scn = dal.scenario_row(sess, session_id, scenario_id)
    if _top_up_refused(sess, session_id, scenario_id, scn, first_generation=first_generation):
        return None
    existing = _existing_map_rows(sess, scn["ScenarioID"])
    manual = str(scn["ScenarioSource"] or "") == str(ContentSource.manual)
    if manual and existing:
        return None
    if not first_generation and any(e.is_live for e in existing):
        return None
    need = s.control_map_min_count - sum(1 for e in existing if e.is_live)
    if need <= 0:
        return None
    min_count, max_count = need, (need if existing else s.control_map_max_count)
    session_row = dal.load_session(sess, session_id)
    if session_row is None:
        # NOT the same fact as "nothing to do". An orphaned or concurrently-deleted session row
        # collapsed into the same silent return as a healthy no-op, so a scenario whose session had
        # vanished was indistinguishable from one already at the floor.
        log.warning("controls.top_up_session_missing", session_id=str(session_id),
                    scenario_id=str(scenario_id))
        return None
    asset_context = _blob(session_row["AssetContextJSON"], {}, column="AssetContextJSON")
    subsystems = _blob(session_row["SubsystemsJSON"], [], column="SubsystemsJSON")
    pool, pool_widened = _top_up_candidate_pool(
        sess, asset_context, subsystems, taken={e.control_library_id for e in existing},
        need=min_count, scenario_id=str(scenario_id))
    scenario = _blob(scn["ScenarioJSON"], {}, column="ScenarioJSON")
    scenario_id = str(scn["ScenarioID"])
    query = _retrieval_query(scn, scenario, asset_name=session_row["AssetName"],
                            asset_technology=asset_context.get("asset_type"),
                            max_chars=s.max_embed_chars)
    if not pool or not query:
        log.warning("controls.top_up_skipped", scenario_id=scenario_id, need=need,
                    pool=len(pool), has_query=bool(query))
        return None
    resolved_itot = _itot_contexts(sess, {scenario_id: scenario}, asset_context,
                                subsystems)[scenario_id]
    cutoff = _min_score(sess, llm, s)
    return _TopUpPlan(
        scenario_id=scenario_id, session_id=str(scn["SessionID"]),
        # The wire's reading of the column (`sessions._scenario_source`): NULL publishes as generated.
        scenario_source=str(scn["ScenarioSource"] or "generated"),
        query=query, need=need, min_count=min_count, max_count=max_count,
        stamp=scn["ControlsMappedAt"] is None,
        existing=existing, pool=pool, pool_widened=pool_widened,
        itot_context=resolved_itot.context, unresolved_systems=resolved_itot.unresolved_systems,
        # The cutoff the MAPPING pass would apply, resolved the same way it resolves it, so the
        # audit's below_min_score is measured against a number that was really in force. `llm` is
        # passed straight through, NEVER `llm or get_llm()`: grounding.resolve_thresholds takes
        # `llm: LLMClient | None` and documents it as "accepted but unused", so constructing a
        # client to fill an unused parameter was pure cost on a path whose whole point is to be
        # cheap enough to fail open.
        min_score=cutoff,
        # The floor is a FRACTION of that cutoff, resolved in the same place for the same reason
        # `_read_mapping_pass` resolves it there: the two are one decision.
        backfill_min_score=_backfill_floor(cutoff.value, s),
        audit_columns={"EntityID": session_row["EntityID"],
                    "SubsystemID": scn["SubsystemID"]})


def _select_top_up(plan: _TopUpPlan, matches, s) -> tuple[control_relevance.ControlSelection,
                                                        list[str]] | None:
    """Phase two's decision: the SAME rule the mapping pass applies, on this scenario's gap.

    `taken` is excluded HERE, from the matches, not from the pool: the pool's exact text list is
    the embedding cache key, while a control the scenario already carries simply must not be
    re-selected (the map PK would refuse it).

    `min_count`/`max_count` come from the plan: a scenario with no rows is sized like the scored
    pass sizes one (floor, everything above the cutoff, the ceiling as a cap); a scenario that has
    rows is filled to the floor and no further — see `_read_top_up_plan`.

    Validation runs BEFORE the caller re-ranks anything: MapRank must read 1..n for the check, and
    the caller then replaces it with this scenario's composite order. Corruption is fail-open here,
    unlike the mapping pass, because this whole path is documented as "the plan proceeds with what
    exists".
    """
    taken = {existing.control_library_id for existing in plan.existing}
    available = [(row, score) for row, score in matches
                if row.get("ControlLibraryID") not in taken]
    selection = control_relevance.select_applicable_controls(
        scenario_id=plan.scenario_id, session_id=plan.session_id, matches=available,
        itot_context=plan.itot_context, preferred_domains=frozenset(),
        min_score=plan.min_score.value, backfill_min_score=plan.backfill_min_score,
        min_count=plan.min_count, max_count=plan.max_count, created_at=now())
    try:
        warnings = control_relevance.validate_control_mapping(
            rows=selection.rows, candidate_ids=[c["ControlLibraryID"] for c in plan.pool],
            itot_context=plan.itot_context, backfill_min_score=plan.backfill_min_score,
            itot_by_control_id={c["ControlLibraryID"]: c.get("ITOT") for c in plan.pool},
            expected_count=plan.min_count)
    except ValueError:
        log.warning("controls.top_up_rejected_corrupt_rows", scenario_id=plan.scenario_id,
                    exc_info=True)
        return None
    if not selection.rows:
        # NOT silent: "the library has nothing for this scenario above the floor" is the answer the
        # old no-cutoff version could never give, and it is why a plan may legitimately be short.
        log.warning("controls.top_up_nothing_above_the_floor", scenario_id=plan.scenario_id,
                    need=plan.need, floor=round(plan.backfill_min_score, 2),
                    cutoff=plan.min_score.value, cutoff_origin=plan.min_score.origin,
                    below_floor=selection.dropped_below_cutoff_count)
        return None
    return selection, warnings


def _merged_control_ranks(plan: _TopUpPlan, added_rows: list[dict]) -> dict[Any, int]:
    """MapRank 1..n for the WHOLE scenario, from THE ONE ordering rule over existing + added.

    THIS IS THE FIX FOR TWO ORDERING IMPLEMENTATIONS. `select_applicable_controls` applied the one
    rule (ITOT-demoted, then score, then domain) to the newly reranked controls, and then
    `renumber_map_ranks_by_score` re-derived MapRank for the entire scenario from Score ALONE —
    discarding the IT/OT demotion and the domain tie-break the first rule had just produced. On any
    topped-up scenario the demotion that the per-scenario ITOT context exists to produce was
    silently undone. That function is DELETED; this one runs the single rule over the merged set,
    which is the only way the two orders cannot disagree.

    ORDERING ONLY. Every row here either already exists in the table or is about to be inserted, so
    the cutoff, the backfill floor and the ceiling are all opened up: `-inf` admits everything and
    `max_count` is the whole set. The selection of WHICH new controls to add already happened in
    `_select_top_up`, under the real floor.

    A NULL-Score existing row (legacy; a person's chosen list never reaches this merge, because a
    manual scenario with any row is not topped up) arrives carrying `_unscored_order_score(its
    rank)`, so it sorts behind every scored row, is never lifted above one, and keeps its place
    among the other unscored rows.
    """
    library_by_id = {row["ControlLibraryID"]: row for row in plan.pool}
    merged = [({"ControlLibraryID": e.control_library_id, "ITOT": e.itot, "Domain": e.domain},
            e.score) for e in plan.existing]
    merged += [(library_by_id.get(row["ControlLibraryID"],
                                {"ControlLibraryID": row["ControlLibraryID"]}), row["Score"])
            for row in added_rows]
    ordered = control_relevance.select_applicable_controls(
        scenario_id=plan.scenario_id, session_id=plan.session_id, matches=merged,
        itot_context=plan.itot_context, preferred_domains=frozenset(),
        min_score=_ADMIT_EVERYTHING, backfill_min_score=_ADMIT_EVERYTHING,
        min_count=0, max_count=len(merged), created_at=now())
    return {row["ControlLibraryID"]: row["MapRank"] for row in ordered.rows}


def _top_up_audit_detail(plan: _TopUpPlan, selection: control_relevance.ControlSelection,
                        warnings: list[str]) -> dict:
    """What the top-up DECIDED, as the audit row's DetailJSON. Every count comes from the
    ControlSelection, so the row cannot report a split the decision did not make.
    """
    picked = [(row["ControlLibraryID"], row["Score"]) for row in selection.rows]
    return {
        "source": "remediation_top_up", "added": len(selection.rows),
        # True only when this write claimed a NULL ControlsMappedAt (D3) — i.e. rows went in on a
        # scenario the scored pass had not settled. The source says which kind of scenario the
        # rows landed on; a manual one here is always the zero-controls case (D1).
        "stamped": bool(plan.stamp and selection.rows),
        "scenario_source": plan.scenario_source,
        "control_library_ids": [cid for cid, _ in picked],
        "scores": [round(score, 2) for _, score in picked],
        # Measured against the cutoff the mapping pass would ACTUALLY use, not the raw setting:
        # _min_score falls back to the calibrated threshold whenever control_map_min_score is
        # unpinned, so comparing to the raw default reported a number against a cutoff that was
        # never applied.
        "effective_min_score": plan.min_score.value,
        "effective_min_score_origin": plan.min_score.origin,
        "effective_backfill_min_score": round(plan.backfill_min_score, 4),
        "below_min_score": sum(1 for _, score in picked if score < plan.min_score.value),
        "cleared_cutoff_count": selection.cleared_cutoff_count,
        "backfilled_count": selection.backfilled_count,
        "itot_demoted_count": selection.itot_demoted_count,
        "itot_labels": list(plan.itot_context.labels),
        "itot_context_source": plan.itot_context.derived_from,
        # Both of these are fail-opens that used to leave no trace. The widened pool drops the ITOT
        # discipline the label filter enforces, and an involved system that resolved to no category
        # narrowed this scenario's ITOT context to its asset's alone — neither is visible in the
        # counts above.
        "itot_pool_widened": plan.pool_widened,
        "unresolved_involved_systems": list(plan.unresolved_systems),
        "warnings": warnings[:20]}


def _write_top_up(plan: _TopUpPlan, selection: control_relevance.ControlSelection,
                warnings: list[str]) -> int:
    """Phase three: one short write transaction — rows, composite ranks, stamp, audit. 0 on any
    failure.

    THE STAMP IS CLAIMED, NOT WRITTEN (D3). On a scenario whose `ControlsMappedAt` was NULL at read
    time the rows and the stamp go in together, and the UPDATE is conditional on the column STILL
    being NULL: rowcount 0 means the scored pass settled this scenario between our read and now, so
    its rows are already in the table and ours must not join them — the transaction is rolled back
    and 0 returned (the plan proceeds from what the scored pass wrote). A stamp only ever lands
    beside rows, so a top-up that found nothing above the floor leaves NULL for the sweep.
    """
    rows = selection.rows
    ranks = _merged_control_ranks(plan, rows)
    for row in rows:
        row["MapRank"] = ranks[row["ControlLibraryID"]]
    # Only the existing rows need an UPDATE, and only when the merge actually moved one; the added
    # rows carry their final rank into the insert below. `else_` leaves every other row alone, so
    # this one statement cannot touch a row it was not asked about.
    reranked = {e.control_library_id: ranks[e.control_library_id] for e in plan.existing
                if ranks[e.control_library_id] != e.map_rank}
    try:
        with db_session() as sess:
            cmap = m.Threat_Scenario_Control_Map
            sess.execute(insert(cmap), rows)
            if plan.stamp and rows:
                out = m.Threat_Scenario
                claimed = sess.execute(update(out).where(out.ScenarioID == plan.scenario_id,
                                                         out.ControlsMappedAt.is_(None))
                                       .values(ControlsMappedAt=now()))
                if claimed.rowcount == 0:
                    # The scored pass got there first. Same transaction, so the insert above goes
                    # with it; db_session's commit on the way out then has nothing to commit.
                    sess.rollback()
                    log.warning("controls.top_up_settled_elsewhere", scenario_id=plan.scenario_id)
                    return 0
            if reranked:
                sess.execute(update(cmap).where(cmap.ScenarioID == plan.scenario_id).values(
                    MapRank=case(reranked, value=cmap.ControlLibraryID, else_=cmap.MapRank)))
            dal.append_audit(
                sess, AuditID=guid(), SessionID=plan.session_id, ScenarioID=plan.scenario_id,
                EventType=AuditEventType.controls_mapped, **plan.audit_columns,
                DetailJSON=json.dumps(_top_up_audit_detail(plan, selection, warnings)))
    except IntegrityError:
        # A concurrent request mapped one of these first (PK ScenarioID+ControlLibraryID).
        log.warning("controls.top_up_conflict", scenario_id=plan.scenario_id)
        return 0
    except Exception:
        log.warning("controls.top_up_write_failed", scenario_id=plan.scenario_id, exc_info=True)
        return 0
    log.info("controls.topped_up", scenario_id=plan.scenario_id, added=len(rows), need=plan.need,
             stamped=plan.stamp)
    return len(rows)


def top_up_scenario_controls(session_id: str, scenario_id: str, *, first_generation: bool = True,
                             authorize: Callable[[Session], object] | None = None,
                             llm: LLMClient | None = None) -> int:
    """Map library controls onto an accepted scenario at plan launch. Returns how many were added.

    WHAT IT FILLS, by owner decision (2026-09-25):

    * an AI scenario short of `control_map_min_count` live controls, up to the floor;
    * a scenario with NO map rows at all — an AI one the scored pass never settled (D3: mapped on
      the spot, and STAMPED when rows were written) or a manual one saved with zero controls (D1)
      — sized as the scored pass sizes it (floor, everything above the cutoff, ceiling as a cap);
    * on a REGENERATE (`first_generation=False`), only a scenario with no live rows (D2).

    A manual scenario with any chosen code is never touched: the person's list is the record.

    Three phases so no transaction is held across the embed + rerank round trips: a short read
    (`_read_top_up_plan`), the grounding (no DB), a short batched write (`_write_top_up`).
    FAIL-OPEN by owner decision — any grounding or write failure logs and returns 0, and the plan
    is generated from the controls already mapped; a NULL stamp is then left NULL for the sweep.
    `authorize` runs first inside the read transaction — the caller's authz boundary.

    THE FLOOR IS NOW THE MAPPING PASS'S OWN. This path used to build its own query, take the
    nearest matches with NO cutoff whatsoever, and count to `remediation_control_min_count` — three
    private rules for the one question `map_controls` was answering next door, which is how a
    remediation plan came to carry a control scoring 3 out of 100. It now calls the same builder
    and the same `select_applicable_controls` with the same backfill floor — now a fraction of
    whichever cutoff `_min_score` resolved, so the two paths cannot diverge even when a fresh
    measurement moves that cutoff — so a scenario the library genuinely cannot cover comes back
    SHORT rather than padded, and
    treatment_input's snapshot already warns the reviewer when the floor was missed.

    `preferred_domains` is deliberately empty here: domain affinity is a tie-break, and the
    per-pass domain embedding it needs belongs to a batch, not to one on-demand request. The policy
    module documents an empty set as a real configuration ("prefer nothing"), not a gap.

    THE FAIL-OPEN COVERS ALL THREE PHASES NOW. It used to wrap only the grounding and the write,
    while phase one — the whole read, including a full Control_Library SELECT and the threshold
    resolve — ran outside any try. A pyodbc timeout there escaped into the HTTP handler and 500'd
    POST /v1/remediation-plans, when the identical failure one phase later logged
    `controls.top_up_failed` and returned 0 so the plan was generated from the controls already
    mapped. `authorize(sess)` is deliberately OUTSIDE that try: it is the caller's authz boundary
    and must keep raising — a 403 that degraded into "we added no controls" would be a hole."""
    s = get_settings()
    if not s.remediation_control_top_up_enabled:
        return 0
    with db_session() as sess:
        if authorize is not None:
            authorize(sess)
        try:
            plan = _read_top_up_plan(sess, session_id, scenario_id, s, llm,
                                     first_generation=first_generation)
        except Exception:
            # Rolled back here, not left for db_session's commit: a failed execute deactivates the
            # transaction, so the commit on the way out would raise PendingRollbackError past this
            # handler and re-open the exact 500 this catch closes.
            sess.rollback()
            log.warning("controls.top_up_failed", session_id=str(session_id),
                        scenario_id=str(scenario_id), phase="read", exc_info=True)
            plan = None
    if plan is None:
        return 0
    try:
        [result] = grounding.ground_control_queries(llm or get_llm(), [(plan.query, None)],
                                                plan.pool, s)
    except Exception:
        log.warning("controls.top_up_failed", scenario_id=plan.scenario_id, exc_info=True)
        return 0
    if not result.answered:
        log.warning("controls.top_up_failed", scenario_id=plan.scenario_id,
                    reason="rerank_unanswered")
        return 0
    decided = _select_top_up(plan, result.matches, s)
    return 0 if decided is None else _write_top_up(plan, *decided)


#: Sessions created before this are NEVER swept. The sweep exists to give the retry queue a
#: consumer GOING FORWARD, not to retro-map work already delivered — an explicit owner decision
#: ("i do not want controls to mapped to the already created sessions"). Moving it backwards
#: would silently start re-examining historical sessions, so it is a constant, not a setting.
CONTROL_MAP_SWEEP_FROM = datetime(2026, 8, 25, 12, 0, tzinfo=UTC)

#: (session, subsystem) pairs handled per sweep tick. Bounded because every mapped output costs a
#: CPU-bound rerank, and one tick must not monopolise a worker slot foreground requests need.
SWEEP_LIMIT = 5


def sessions_awaiting_control_mapping(sess: Session, limit: int = SWEEP_LIMIT) -> list[tuple[str, int, int]]:
    """(SessionID, SubsystemID, GenerationEpoch) for work stranded in the control-mapping queue.

    THE QUEUE HAD NO CONSUMER. `map_controls` selects on `ControlsMappedAt IS NULL` and three of
    its paths deliberately return without stamping — `controls.no_candidates`,
    `controls.lease_lost`, and a per-output unanswered rerank — each documented as safe because
    "the row just stays in the queue and the next run retries it". But `map_controls` is called
    only from `_finalize_scenario_batch`, i.e. the tail of a scenario batch for that same session,
    so once a session finished nothing ever mapped it again. Every "recoverable" path was in fact
    permanent: one 429 during a session's only pass and that scenario had no controls forever,
    published as `controls: []`, which the API documents as a genuine library gap. This function
    is the missing SELECT that makes "left for retry" true.

    Two fences make a swept row provably nobody else's work:

    * the SCENARIOS stage must be SETTLED (AWAITING_DECISION/COMPLETE) — a RUNNING stage means a
      live batch owns the session and will map at its own tail;
    * settled for longer than one `stage_lease_seconds` — `_finalize_scenario_batch` calls
      `finish_stage` BEFORE `map_controls`, so settledness alone leaves a window where the
      in-pipeline mapping is still running. The lease is the codebase's own definition of "a work
      step this old is no longer alive", so no second grace knob is invented.

    The epoch comes from that same settled row, which is what lets the reused `map_controls` pass
    its own `stage_settled_at_epoch` fallback: the sweep holds no stage claim, so `renew_lease`
    correctly fails and the settled check is what authorises it.

    A HAND-WRITTEN scenario is never swept, by the same column test `eligible_outputs` applies —
    see `_not_hand_written`. Listed apart from the two fences above because it is not a question of
    who owns the work: there is no work for THIS queue. A person chose those controls and that is
    the record; a person who chose none gets them from the plan-launch top-up (D1), never from
    here. This queue is the only path that can reach a finished session, so before the source test
    existed it was also the one that a cleared ControlsMappedAt would have opened onto a manual
    row — and unlike `eligible_outputs` this query has no map-row condition to fall back on, so
    the stamp was its ONLY provenance guard.

    The stamp is still what keeps an AI scenario the top-up mapped at plan launch out of here: that
    write sets ControlsMappedAt beside its rows (`_write_top_up`), and a top-up that wrote nothing
    leaves NULL, so the sweep still owns the scenario.
    """
    out, ses, st = m.Threat_Scenario, m.Scenario_Session, m.Subsystem_Stage_State
    cutoff = now() - timedelta(seconds=get_settings().stage_lease_seconds)
    rows = sess.execute(
        select(out.SessionID, out.SubsystemID, st.GenerationEpoch)
        .join(ses, ses.SessionID == out.SessionID)
        .join(st, (st.SessionID == out.SessionID)
                & (st.SubsystemID == out.SubsystemID)
                & (st.Level == SubsystemLevel.SCENARIOS))
        .where(out.Status == ScenarioStatus.complete,
            # NOT `active(Superseded)` alone. An ACCEPTED output that was later superseded is
            # still rendered by /results (its `replaced_scenarios` history, pinned by
            # test_accept_any_version.py) — controls and all — so excluding it published a
            # permanent empty control list on a scenario a reviewer can see and has signed off.
            or_(dal.active(out.Superseded), out.Accepted == 1),
            out.ControlsMappedAt.is_(None),
            _not_hand_written(out.ScenarioSource),
            _under_attempt_limit(out.ControlMapAttempts),
            ses.CreatedAt >= CONTROL_MAP_SWEEP_FROM,
            st.Status.in_([StageStatus.AWAITING_DECISION, StageStatus.COMPLETE]),
            st.UpdatedAt < cutoff)
        .group_by(out.SessionID, out.SubsystemID, st.GenerationEpoch)
        # LIMIT without ORDER BY is an arbitrary TOP-N on SQL Server, and an ARBITRARY set can be
        # a STABLE one: pair that with a session that always fails and the optimiser can hand back
        # the same doomed five every tick while everything behind them starves. Oldest first is
        # deterministic AND serves the longest-waiting session, so the queue always drains.
        # MIN() because UpdatedAt is not a GROUP BY key; the stage row is unique per
        # (session, subsystem, level), so the aggregate is that row's own value.
        .order_by(func.min(st.UpdatedAt))
        .limit(limit)
    ).all()
    return [(str(r[0]), int(r[1]), int(r[2])) for r in rows]
