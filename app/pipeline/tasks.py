from __future__ import annotations

import difflib
import json
from collections.abc import Callable
from datetime import datetime
from typing import Any, NamedTuple

from sqlalchemy import func, insert, update
from sqlalchemy.orm import Session

from app.core import tuning
from app.core.config import get_settings
from app.core.enums import (
    AuditEventType,
    ScenarioStatus,
    ScopingRejection,
    SelectionReason,
    SessionStatus,
    SSEEventType,
    StageStatus,
    SubsystemLevel,
    WorkflowStage,
)
from app.core.logging import get_logger
from app.core.security import _redact_value, is_placeholder
from app.core.tracing import trace_step
from app.db import dal
from app.db import models as m
from app.db.dal import execute_dml, guid, now, span_seconds
from app.db.engine import db_session
from app.intel import fetchers as intel
from app.intel.fetchers import IntelTerms
from app.pipeline import (
    control_mapping,
    prompts,
    scoping,
    validation,
)
from app.pipeline.llm import (
    LLMClient,
    LLMRefusal,
    LLMResponseTruncated,
    LLMSlotUnavailable,
    Provenance,
    moderate,
)

# --- Structure pass: Stage-1 threat identification and the shared stage primitives live
# --- in their own modules now. These RE-EXPORTS keep every external import path working
# --- unchanged: dal.identity_hash lazily imports tasks._dedup_key, promote.py imports
# --- asset_agnostic_name, cascade.py calls tasks.find_threats/tasks.threat_label, and
# --- the tests import the underscored helpers — all via `app.pipeline.tasks`, as before.
# --- The per-name F401 suppressions below say the same thing to ruff: re-export, not dead
# --- import. They sit only on names this module does not itself call (RUF100 removes any
# --- that stops being needed), so the list stays honest as the split settles.
from app.pipeline.pipeline_common import (
    _EPOCH,
    _WORK_LEVELS,
    ASSET_UNIT_ID,
    TRANSIENT_INFRA_ERRORS,
    _ask_ai,
    _asset_boundary_pattern,  # noqa: F401
    _dedup_key,
    _normalize,  # noqa: F401
    _safe_text,  # noqa: F401
    _send_live_update,
    _summarize_ai_call,
    asset_agnostic_name,  # noqa: F401
    clean_library_name,  # noqa: F401
    log_transient_infra_retry,
    set_up_progress_tracking,  # noqa: F401
    threat_label,  # noqa: F401
)
from app.pipeline.threat_identification import (
    _build_retrieved_records,  # noqa: F401
    _build_threat_records,  # noqa: F401
    _duplicate_row,  # noqa: F401
    _gap_ask,  # noqa: F401
    _generic_name_of,  # noqa: F401
    _semantic_duplicates,  # noqa: F401
    _usable_category,  # noqa: F401
    _usable_proposal,  # noqa: F401
    find_threats,
)
from app.sse import bus

log = get_logger(__name__)

_SCENARIO_TEXT_FIELDS = ("scenario_title", "scenario_statement", "risk_statement")

#: Subsystem fields that name a PRODUCT — a vendor, technology or platform — the intel search's
#: regex tier (IntelTerms.product). Management labels (managed_by, hosting_location,
#: accessability_channel, targeted_users) were dropped 2026-09-02: "In-house", "Outsourced",
#: "Internal users" are not product names and only ever matched noise. Subsystem asset_type is
#: excluded too — it's an IT/OT label; category CODES drive the prefer-order instead. Sector,
#: sub_sector and critical_service go to IntelTerms.scope (structured equality), never here.
_INTEL_TECH_FIELDS = ("technology_used", "vendor_name", "database_platforms",
                    "saas_platform_list", "public_cloud_platforms")

#: Inventory dropdown values that name a CATEGORY, not a product. They clear the 4-char minimum
#: but only ever match noise ("Cloud" hits every pulse tagged `cloud c2`). Compared casefolded;
#: is_placeholder still handles the NA/Unknown family.
_GENERIC_INVENTORY_VALUES = frozenset({
    "cloud", "other", "others", "custom", "custom application", "application", "web application",
    "database", "internal", "external", "legacy", "in-house", "outsourced", "on-premise",
    "on-premises", "hybrid", "saas", "paas", "iaas"})

class RegenTarget(NamedTuple):
    scenario_id: str
    threat_id: str
    scoped_threat_id: str
    scenario_number: int
    identity_hash: str | None

class _ScenarioFold(NamedTuple):
    rows: list
    siblings_by_hash: dict
    cross_pairs: list
    frozen_by_hash: dict


class _ScenarioBatch(NamedTuple):
    base_ctx: dict
    enriched: dict
    deduped: int
    pairs: list
    scoped_count: int
    fold: _ScenarioFold
    entry_vocab: dict
    intel_terms: IntelTerms
    # Resolved once per batch beside intel_terms; None = no asset preference.
    technique_labels: list[str] | None = None

class _Coverage(NamedTuple):
    vocab: dict
    frozen: list | None
    others: list | None
    # Intel search terms from _intel_vocabulary. Defaults to None so old callers that don't
    # pass this still work — missing terms just mean "no intel block", not a crash.
    intel_terms: IntelTerms | None = None
    # Technique families suiting this asset (_technique_asset_labels). None = no asset
    # preference, which is also what the resolver returns for a partly representable asset.
    technique_labels: list[str] | None = None


def _flag_sibling_similarity(report: dict, scenario: dict, sibling_texts: list[tuple[int, str]],
                            ratio: float) -> None:
    statement = str(scenario.get("scenario_statement") or "")
    if not statement.strip():
        return
    for number, sibling_statement in sibling_texts:
        if not sibling_statement.strip():
            continue
        if difflib.SequenceMatcher(None, statement, sibling_statement).ratio() >= ratio:
            report["errors"] = list(report.get("errors") or [])
            report["errors"].append(
                f"scenario is very similar to this threat's other scenario (scenario #{number})")
            report["validation_status"] = "warning"
            return




def _statement_of(scenario_json: str | None) -> str:

    try:
        return str((json.loads(scenario_json or "{}") or {}).get("scenario_statement") or "")
    except (TypeError, ValueError):
        return ""

# Turn a session's scenario rows into a structure used to check for similar scenarios and
# to find each identity hash's primary scenario (the one with the lowest scenario number).
def _fold_scenario_rows(rows: list) -> _ScenarioFold:    
    siblings: dict[str, list[tuple[str, int, str]]] = {}
    cross: list[tuple[str, str]] = []
    frozen: dict[str, list[int]] = {}
    primary_number: dict[str, int] = {}
    for r in rows:
        if r.Status != ScenarioStatus.complete:
            continue
        statement = _statement_of(r.ScenarioJSON)
        siblings.setdefault(r.IdentityHash, []).append((r.ScenarioID, r.ScenarioNumber, statement))
        if statement.strip():
            cross.append((r.IdentityHash, statement))
        if r.ScenarioNumber < primary_number.get(r.IdentityHash, 1 << 30):
            primary_number[r.IdentityHash] = r.ScenarioNumber
            ids = dal._entry_ids(r.ScenarioJSON, "plausible_entry_point_ids")
            if ids:
                frozen[r.IdentityHash] = ids
            else:
                frozen.pop(r.IdentityHash, None)
    return _ScenarioFold(rows, siblings, cross, frozen)


def _flag_cross_threat_similarity(report: dict, scenario: dict, other_texts: list[str],
                                ratio: float) -> None:
    statement = str(scenario.get("scenario_statement") or "")
    if not statement.strip():
        return
    for other in other_texts:
        if not other.strip():
            continue
        if difflib.SequenceMatcher(None, statement, other).ratio() >= ratio:
            report["errors"] = list(report.get("errors") or [])
            report["errors"].append(
                "scenario is very similar to an active scenario of ANOTHER threat in this session")
            report["validation_status"] = "warning"
            return




# Runs the moderation check on a scenario's three prose fields. Controls are no longer part
# of the moderated text: the LLM stops proposing them (library-first redesign), and library
# control names are curated data that never needs moderating.
# Returns {"checked": ok?, "flagged": found something?, "categories": [...], "error": str|None}.
def _moderation_report(scenario: dict) -> dict:
    text = " ".join(str(scenario.get(f) or "") for f in _SCENARIO_TEXT_FIELDS)
    r = moderate(text)
    return {"checked": r.checked, "flagged": r.flagged, "categories": r.categories, "error": r.error}


def _intel_vocabulary(sess: Session, subsystems: list[dict], asset_context: dict) -> IntelTerms:
    """Build the threat-intel search terms from the asset's inventory and classification —
    never from the threat's own wording: threat names use generic business language
    ("failure", "maintenance", "system") that matches everyday IT advisories, which is how a
    power-plant search once pulled Cisco/Fortinet/SharePoint CVEs while the ICS advisories
    were ignored.

    product: vendor / technology / platform names from _INTEL_TECH_FIELDS plus the asset's
             operating_system, placeholders ("NA", "Unknown") dropped via is_placeholder.
    scope:   canonical sector keys from sector / sub_sector / critical_service (fixed dropdown
             values such as "Energy", "Power Transmission" → 'sector:energy') plus the
             configured home country — matched by equality against each item's structured
             scope_tags, so a sector word can never hit an unrelated title by coincidence.
    categories: ctm_scan_category codes (IT / OT / ...) — DB-resolved, not text-matched; one OT
             component anywhere is enough for ICS advisories to be drawn first."""
    product: list[str] = []
    seen: set[str] = set()

    def _add(value: Any) -> None:
        for v in value if isinstance(value, (list, tuple)) else [value]:
            text = str(v).strip() if v is not None else ""
            key = text.casefold()
            if text and not is_placeholder(text) and key not in _GENERIC_INVENTORY_VALUES and key not in seen:
                seen.add(key)
                product.append(text)

    for sub in subsystems or []:
        for fld in _INTEL_TECH_FIELDS:
            _add(sub.get(fld))
    _add(asset_context.get("operating_system"))
    scope = intel.sector_keys([asset_context.get(k) for k in ("sector", "sub_sector", "critical_service")])
    home = get_settings().intel_home_country
    if home:
        scope += intel.country_keys(home)
    return IntelTerms(product=product, scope=scope,
                      categories=control_mapping.session_category_codes(sess, subsystems, asset_context))


def _prefer_kinds(categories: set[str]) -> tuple[str, ...]:
    """Which intel kind is drawn first, by asset category. OT anywhere wins: a plant with one
    IT historian still wants ICS advisories first. Pure IT wants exploited CVEs first. The
    non-technical categories (data, human roles, facilities, physical) have no CVE surface of
    their own, so campaign reports lead."""
    codes = {c.upper() for c in categories}
    if "OT" in codes:
        return ("ics_advisory", "cve", "pulse")
    if "IT" in codes:
        return ("cve", "pulse", "ics_advisory")
    return ("pulse", "cve", "ics_advisory")


def _fetch_intel(terms: IntelTerms | None, actors: list[str] | None = None,
                limit: int | None = None) -> list[dict] | None:
    """Fetches threat-intel items to inject into the prompt; prompts._intel_block just
    renders whatever this returns. With no product AND no scope terms, no block is sent."""
    s = get_settings()
    if not s.intel_enabled or terms is None or not (terms.product or terms.scope):
        return None
    if limit is None:
        limit = s.prompt_intel_limit
    try:
        prefer = _prefer_kinds(terms.categories)
        items = intel.query_intel(terms, prefer_kinds=prefer, limit=limit)
        actor_terms = [a for a in (actors or []) if a]
        if actor_terms:
            # One reserved slot for a report ATTRIBUTED to this threat's actor (equality on the
            # pulse's adversary — a role label like "Cybercriminal" matches nothing).
            pulses = intel.query_actor_pulses(actor_terms, limit=1)
            if pulses:
                seen = {(p["source"], p["external_id"]) for p in pulses}
                items = pulses + [i for i in items
                                if (i["source"], i["external_id"]) not in seen]
                items = items[:limit]
        if items:
            # Everything an audit needs to judge relevance without recomputing: the terms
            # searched and, per item, WHICH tier admitted it.
            log.info("scenario.intel_injected", prefer=prefer, product_terms=terms.product,
                    scope_keys=terms.scope,
                    items=[{"id": i.get("external_id"), "kind": i.get("kind"),
                            "via": i.get("matched_via")} for i in items])
        return items or None
    except Exception:
        log.warning("scenario.intel_fetch_failed", exc_info=True)
        return None


def _fetch_techniques(llm, threat_type: str | None, threat_name: str | None,
                    category: str | None, *, asset_labels: list[str] | None = None,
                    limit: int = 4) -> list[dict] | None:
    """Published ATT&CK/CAPEC techniques nearest THIS threat, for prompts._technique_block.

    Keyed on the threat, not the asset — that is the whole reason this corpus is separate from
    the intel feed, whose product/scope tiers can never match a technique (see
    app/intel/technique_reference's module docstring).

    `asset_labels` is a SET of technique families, resolved once per batch by
    _technique_asset_labels through the same rule the control filter uses. None means no asset
    preference -- including the case where the asset's nature is only partly representable, which
    must NOT narrow (see that helper). The STRIDE mask applies regardless.

    Fail-open exactly like _fetch_intel: any failure returns None, no block is emitted, and the
    prompt is byte-for-byte the pre-feature one."""
    query = " ".join(p for p in (threat_type, threat_name) if p).strip()
    if not query:
        return None
    try:
        from app.intel.technique_reference import lookup

        items = lookup(llm, query, stride=category, asset_labels=asset_labels, k=limit)
        if items:
            log.info("scenario.technique_reference_injected", threat_type=threat_type,
                    stride=category, asset_labels=asset_labels,
                    items=[i.get("id") for i in items])
        return items or None
    except Exception:
        log.warning("scenario.technique_fetch_failed", exc_info=True)
        return None

def _technique_asset_labels(sess: Session, subsystems: list[dict], asset_context: dict) -> list[str] | None:
    """Which technique families suit this session's asset, or None for "no preference".

    Resolved through grounding.resolve_asset_labels -- the SAME rule the control-pool filter
    uses -- against the vocabulary the technique corpus actually carries. That matters: the rule
    returns None whenever any of the session's categories cannot be represented, so an asset that
    is OT *and* Physical is never silently narrowed to OT-only. Narrowing on a partly
    representable asset is a documented past defect, not a hypothetical, and hardcoding "OT" here
    would have reintroduced it.

    Computed ONCE per scenario batch and carried on _Coverage beside intel_terms, not per threat:
    it costs a category query plus a corpus read."""
    try:
        from app.intel.technique_reference import corpus_vocabulary
        from app.pipeline import grounding, threat_retrieval

        return grounding.resolve_asset_labels(
            sess,
            threat_retrieval.session_category_ids(subsystems, asset_context),
            corpus_vocabulary,
            log_event="scenario.technique_category_without_vocabulary_no_filter")
    except Exception:
        log.warning("scenario.technique_labels_failed", exc_info=True)
        return None


def _ground_entry_points(scenario: dict, vocab: dict[str, int],
                        frozen: list[int] | None = None) -> None:
    """Resolves the AI's two returned lists against `vocab`, attaching real ids and enforcing
    at most one `is_entry_point: true`. `supporting_systems_involved` is the PUBLIC field — only
    what this scenario's own narrative is actually about. `plausible_entry_point_ids` stays
    internal (schemas.py excludes it from the API response): it is
    dal.variant_eligible_primaries's coverage target for whether a THREAT needs another scenario
    variant, not a claim about what THIS scenario is about."""
    by_fold = {label.casefold(): (label, sid) for label, sid in vocab.items()}

    def _resolve(raw: Any) -> tuple[str, int] | None:
        return by_fold.get(raw.strip().casefold()) if isinstance(raw, str) else None

    raw_involved = scenario.get("supporting_systems_involved")
    involved: list[dict] = []
    entry_id: int | None = None
    saw_primary = False
    for row in (raw_involved if isinstance(raw_involved, list) else []):
        if not isinstance(row, dict):
            continue
        hit = _resolve(row.get("supporting_system"))
        if not hit:
            continue  # never invented — a name outside vocab is dropped, not stamped through
        label, sid = hit
        claims_primary = bool(row.get("is_entry_point"))
        is_primary = claims_primary and not saw_primary
        if claims_primary and not is_primary:
            log.warning("scenario.multiple_primary_entry_points_demoted", supporting_system=label)
        saw_primary = saw_primary or is_primary
        if is_primary:
            entry_id = sid
        involved.append({"supporting_system_id": sid, "supporting_system": label,
                        "is_entry_point": is_primary,
                        "justification": row.get("justification") or ""})
    scenario["supporting_systems_involved"] = involved

    plausible_ids: list[int] = [entry_id] if entry_id is not None else []
    for raw in (scenario.get("plausible_entry_points") or []):
        hit = _resolve(raw)
        if hit and hit[1] not in plausible_ids:
            plausible_ids.append(hit[1])
    scenario["plausible_entry_point_ids"] = list(frozen) if frozen else plausible_ids
    scenario.pop("plausible_entry_points", None)  # coverage-planning names, superseded by _ids


def _generate_one_scenario(sess: Session, scenario_session: dict, base_ctx: dict, sc,
                    enriched: dict, llm: LLMClient, task_id: str, epoch: int,
                    sibling_texts: list[tuple[int, str]] | None = None,
                    coverage: _Coverage | None = None,
                    # Per-item id stamped onto BOTH Prompt_Log rows this call can write (the
                    # generation attempt and its repair turn), so a receipt joins back to the
                    # scenario it produced. Callers pass the ScopedThreatID.
                    *, correlation_id: str | None = None) -> tuple[dict, dict, Provenance | None]:    
    info = enriched.get(sc.threat_id, {})
    threat_type = info.get("library_threat_type") or info.get("threat_type")
    threat_name = info.get("library_threat_name") or info.get("threat_name")
    actors = info.get("actors") or []
    # [A2] STRIDE category, already available from find_threats — no extra query needed. Used
    # to steer the scenario's shape (prompts._STRIDE_SCENARIO_SHAPES); if missing, prompt is
    # unaffected.
    category = info.get("category")
    tn = tuning.from_session(scenario_session)  # tuning settings frozen at session start, not live config
    # Fall back to an empty coverage when the caller doesn't have one yet.
    cov = coverage or _Coverage(vocab={}, frozen=None, others=None)
    # Intel is matched using the tech-inventory terms from coverage, never threat wording.
    intel_items = _fetch_intel(cov.intel_terms, actors, limit=tn.prompt_intel_limit)
    technique_items = _fetch_techniques(llm, threat_type, threat_name, category,
                                        asset_labels=cov.technique_labels)
    # The set of IDs the model was allowed to cite. Left as None (not an empty set) when no
    # intel was sent at all, so validation skips the citation check instead of failing every id.
    injected_intel_ids = ({str(i.get("external_id")) for i in intel_items if i.get("external_id")}
                        if intel_items else None)
    entry_labels = sorted(cov.vocab) if cov.vocab else None
    if sibling_texts:
        messages = prompts.variant_scenario_prompt(base_ctx, threat_type, threat_name, actors=actors,
                                                intel_items=intel_items,
                                                technique_items=technique_items,
                                                existing=sibling_texts,
                                                entry_points=entry_labels,
                                                sibling_k=tn.variant_sibling_prompt_k,
                                                category=category)
    else:
        messages = prompts.scenario_prompt(base_ctx, threat_type, threat_name, actors=actors,
                                        intel_items=intel_items,
                                        technique_items=technique_items,
                                        entry_points=entry_labels, category=category)
    scenario, prov = _ask_ai(sess, llm, messages,
                            scenario_session=scenario_session, subsystem_id=ASSET_UNIT_ID, stage="scenario",
                            level=SubsystemLevel.SCENARIOS, epoch=epoch, task_id=task_id, expected_type=dict,
                            correlation_id=correlation_id,
                            temperature=get_settings().scenario_generation_temperature)
    # Use critical_service from base_ctx (what the model actually saw), not the raw
    # asset_context — placeholder values like "Unknown"/"TBD" are scrubbed out there, and
    # validation shouldn't require a value the model was never shown.
    report = validation.validate_scenario(
        scenario, threat_type, threat_name,
        asset_name=scenario_session["AssetName"],
        critical_service=base_ctx["asset_context"].get("critical_service"),
        injected_intel_ids=injected_intel_ids)
    # One retry to fix STRUCTURAL problems only (missing required fields) — never for
    # advisory warnings, which are just informational. We tell the model not to change the
    # facts, so this can't turn into a free reroll that dodges the similarity check below.
    # The retry is only accepted if it actually fixes more missing fields; if it fails to
    # parse, we just keep the original. Runs before moderation/grounding/similarity checks
    # so those all see the final version.
    missing = [e for e in report["errors"] if e.startswith("missing ")]
    if missing:
        repair_messages = [*messages,
            # Scrub DB ids like any other payload. Currently a no-op since this runs before
            # _ground_entry_points adds any ids — but it's safe even if that order changes later.
            {"role": "assistant", "content": json.dumps(prompts._scrub_db_keys(scenario))},
            {"role": "user", "content":
                "The previous response failed validation: " + "; ".join(missing) +
                ". Correct only these violations. Do not change factual content unless "
                "required. Return only the corrected JSON object."}]
        try:  # through _ask_ai, so Prompt_Log keeps both attempts and the stage lease renews
            repaired, r_prov = _ask_ai(sess, llm, repair_messages,
                                    scenario_session=scenario_session, subsystem_id=ASSET_UNIT_ID,
                                    stage="scenario", level=SubsystemLevel.SCENARIOS, epoch=epoch,
                                    task_id=task_id, expected_type=dict,
                                    # Deliberately the SAME id as the attempt above: CorrelationID
                                    # has no unique constraint and the evidence read returns every
                                    # matching row ordered by CreatedAt, so the two attempts group.
                                    correlation_id=correlation_id,
                                    temperature=get_settings().scenario_generation_temperature)
        except Exception:
            # Must roll back here. _ask_ai runs DB commits before and after the LLM call, over
            # a connection that stays open for the whole call — if it drops mid-call, the
            # session is left needing a rollback. Skip this and the next DB call outside this
            # try (the lease renewal in write_scenarios) would fail and mark the whole
            # SCENARIOS stage as errored, throwing away an already-generated, already-billed
            # scenario just because an optional repair attempt failed.
            sess.rollback()
            # This repair is optional: the original scenario already generated and passed
            # validation (maybe with warnings), so a failed repair must never destroy it. We
            # catch everything here on purpose — parse errors, provider errors, and
            # LLMSlotUnavailable should all just fall back to keeping the original. In
            # particular, letting LLMSlotUnavailable propagate would make Celery retry (and
            # re-bill) the whole stage just because a repair attempt couldn't find a slot.
            log.warning("scenario.repair_failed", session_id=scenario_session["SessionID"],
                        threat_id=sc.threat_id, exc_info=True)
        else:
            # Merge the repair into the original, never replace it outright. The model is
            # asked for "the corrected JSON object" but can legally return just a partial one
            # (e.g. only {"risk_statement": "..."}). Replacing wholesale would then silently
            # delete fields like supporting_systems_involved, which would permanently cap this
            # threat at one scenario without any visible error. Merging means a repair can only
            # overwrite fields it actually returned — it can never accidentally delete one.
            merged = {**scenario, **repaired}
            # A merge can still accidentally EMPTY a field, though, which is just as bad as
            # deleting it: if the repair explicitly returns "supporting_systems_involved": [] or
            # "plausible_entry_points": [], that's a valid value that would overwrite the
            # original and freeze the threat at one scenario. So keep the original list whenever
            # the repair's version is empty, for both raw AI-output lists _ground_entry_points
            # (called AFTER this) still needs to read.
            for key in ("supporting_systems_involved", "plausible_entry_points"):
                if not merged.get(key):
                    merged[key] = scenario.get(key) or []
            # Validate the MERGED scenario, not just the raw repair — otherwise the saved
            # validation report could describe a different scenario than what actually gets
            # saved as ScenarioJSON.
            r_report = validation.validate_scenario(
                merged, threat_type, threat_name,
                asset_name=scenario_session["AssetName"],
                critical_service=base_ctx["asset_context"].get("critical_service"),
        injected_intel_ids=injected_intel_ids)
            still = [e for e in r_report["errors"] if e.startswith("missing ")]
            if len(still) < len(missing):
                scenario, report, prov = merged, r_report, r_prov
                log.info("scenario.repaired", session_id=scenario_session["SessionID"],
                        threat_id=sc.threat_id, was_missing=missing, still_missing=still)
    report["moderation"] = _moderation_report(scenario)
    
    _ground_entry_points(scenario, cov.vocab, cov.frozen)
    if sibling_texts:
        _flag_sibling_similarity(report, scenario, sibling_texts, tn.sibling_similarity_ratio)
    if cov.others:
        _flag_cross_threat_similarity(report, scenario, cov.others, tn.sibling_similarity_ratio)
    return scenario, report, prov


def _build_scoped_threat_row(scoped_id: str, sid: str, tenant: str, ss: int, sc: scoping.Scored,
                        entity_id: str | None, user_id: str | None) -> dict:
    return {
        "ScopedThreatID": scoped_id, "SessionID": sid, "TenantID": tenant, "EntityID": entity_id,
        "UserID": user_id, "SubsystemID": ss,
        "ThreatID": sc.threat_id, "Score": sc.score, "ScopeRank": sc.rank,
        "Selected": 1 if sc.selected else 0, "Reason": sc.reason, "RejectionKind": sc.rejection,
        "SelectionKind": sc.selection,
        "FactorsJSON": json.dumps(sc.factors) if sc.factors else None,
        "Superseded": 0, "CreatedAt": now(),
    }


def _scrub_model_output(scenario: dict, sid: str, threat_id: str | None) -> dict:
    """Outbound twin of the inbound redaction [gap-8]: the model's own text runs through the same
    _SECRET_PATTERNS before persistence, so /results, the Excel export and the audit trail all
    inherit the scrub from this one write-side point. Residual risk (unlabeled prose credentials,
    invented person names) stays documented in validation.validate_scenario.

    MUST NEVER RAISE: a paid generation is never lost to cleanup — on any error the original is
    stored and the failure logged (same advisory-tail discipline as _publish_regen_result)."""
    try:
        cleaned = _redact_value(scenario)
        if cleaned != scenario:
            log.info("scenario.output_redacted", session_id=sid, threat_id=threat_id)
        return cleaned
    except Exception:
        log.exception("scenario.output_scrub_failed", session_id=sid, threat_id=threat_id)
        return scenario


def _stamp_generation_span(started: datetime, step) -> tuple[datetime, datetime]:
    """Close one scenario's generation span: record its seconds on the trace step and return
    (started, finished) for the caller to carry to the row.

    An EXPLICIT channel, on purpose. The span used to ride inside `report` and be popped out by
    the row builder - which meant a scenario that FAILED, and so never produced a report, had no
    span at all: the failure card published gen_seconds=null while the trace file recorded the
    duration. The batch tuple now carries the span for every item, success or failure, and both
    row builders take it as a required keyword - a call site that forgets it is a TypeError, not
    a silent NULL. (scripts/test_pipeline_guards.py pins the three _generate_one_scenario call
    sites; nothing here touches them.)

    dal.now() (wall clock), not perf_counter: these are TIMESTAMPS, and their overlap across rows
    is the whole point. Generation fans out scenario_generation_concurrency at a time, so several
    scenarios legitimately share a start - recording both ends makes that visible in the data
    instead of leaving it as a caveat about why per-scenario durations do not sum to the stage.
    """
    finished = now()
    step.result(seconds=span_seconds(started, finished))
    return started, finished


def _build_scenario_output_row(scoped_id: str, sid: str, tenant: str, ss: int, scenario: dict, report: dict,
                            epoch: int, entity_id: str | None, user_id: str | None, info: dict,
                            scenario_number: int = 1, replaces_scenario_id: str | None = None,
                            source: str = "generated", *,
                            span: tuple[datetime, datetime]) -> dict:

    scenario = _scrub_model_output(scenario, sid, info.get("threat_id"))
    identity = dal.identity_hash(sid, ss, info)
    return {
        "ScenarioID": guid(), "SessionID": sid, "TenantID": tenant, "EntityID": entity_id, "UserID": user_id,
        "SubsystemID": ss,
        "ScopedThreatID": scoped_id, "Status": ScenarioStatus.complete,
        "ScenarioJSON": json.dumps(scenario),
        "ValidationJSON": json.dumps(report),
        "Accepted": 0, "Superseded": 0,
        "IdentityHash": identity, "ScenarioNumber": scenario_number,
        "ReplacesScenarioID": replaces_scenario_id,
        "GenerationEpoch": epoch, "ErrorMessage": None, "CreatedAt": now(),
        # The generation span, in its own columns and NOT in ValidationJSON: one copy of the
        # fact. CreatedAt above is when this ROW WAS PERSISTED - the batch persists sequentially
        # once every scenario has finished generating - so it is a different fact.
        "GenStartedAt": span[0], "GenFinishedAt": span[1],
        # "library" = this text was written for another asset of the SAME profile and had its
        # system names swapped in; anything else was written for this asset. A reviewer signing
        # the register has to be able to tell, so it is persisted, never inferred.
        "ScenarioSource": source,
    }


def _build_error_output_row(scoped_id: str, sid: str, tenant: str, ss: int, client_msg: str,
                            epoch: int, entity_id: str | None, user_id: str | None, info: dict,
                            scenario_number: int = 1, replaces_scenario_id: str | None = None,
                            *, span: tuple[datetime, datetime]) -> dict:
    return {
        "ScenarioID": guid(), "SessionID": sid, "TenantID": tenant, "EntityID": entity_id, "UserID": user_id,
        "SubsystemID": ss,
        "ScopedThreatID": scoped_id, "Status": ScenarioStatus.error,
        "ScenarioJSON": None, "ValidationJSON": None,
        "Accepted": 0, "Superseded": 0,
        "IdentityHash": dal.identity_hash(sid, ss, info), "ScenarioNumber": scenario_number,
        "ReplacesScenarioID": replaces_scenario_id,
        "GenerationEpoch": epoch,
        "ErrorMessage": client_msg, "CreatedAt": now(),
        # A failure has a span too - how long it burned before falling over is the most useful
        # number a failure card can carry (a 120s timeout reads nothing like an instant reject).
        "GenStartedAt": span[0], "GenFinishedAt": span[1],
    }


def _select_unique_top_n(scoped: list[scoping.Scored], enriched: dict, top_n: int | None) -> int:

    seen: set[str] = set()
    kept = 0
    deduped = 0
    for sc in scoped:
        if not sc.selected:
            continue
        key = _dedup_key(enriched.get(sc.threat_id, {}))
        if key in seen:
            # This branch should never actually run — find_threats already de-dupes by this
            # same key before threats get here. Kept as a safety net anyway, since it's the
            # last check before a duplicate would trigger a paid scenario generation, and the
            # code that guarantees uniqueness lives in a different function. If `deduped` ever
            # goes above 0, that's a bug elsewhere, not evidence this check is doing real work.
            log.warning("scoping.duplicate_survived_identity_dedup",
                        threat_id=sc.threat_id, dedup_key=key)
            sc.selected, sc.reason = False, "duplicate of higher-ranked threat"
            # selection cleared WITH the demotion — `selection is not None ⟺ selected` is a
            # persisted contract (SelectionKind must be NULL on every Selected=0 row)
            sc.rejection, sc.selection = ScopingRejection.duplicate, None
            deduped += 1
        elif top_n is not None and kept >= top_n:
            sc.selected, sc.reason = False, f"beyond top-{top_n} cutoff"
            sc.rejection, sc.selection = ScopingRejection.top_n_cutoff, None
        else:
            seen.add(key)
            kept += 1
    return deduped


def _mark_next_set_targets_rescored_out(sess: Session, sid: str, ss: int, pairs: list, excluded_ids: set[str],
                                    tenant: str, entity_id: str | None, user_id: str | None) -> None:
    excluded_needing_marker = (excluded_ids - dal.threats_with_active_scenario(sess, sid, ss, excluded_ids)
                            if excluded_ids else set())
    if not excluded_needing_marker:
        return
    # Must retire outputs BEFORE the scoped rows: supersede_outputs_for_threats finds outputs
    # through their scoped row, so once that's retired it can no longer find them. Without
    # this order, a threat whose only output is a failure card (which doesn't count as an
    # "active scenario") would keep showing that stale card in /results even after its
    # parent threat disappears from the list.
    dal.supersede_outputs_for_threats(sess, sid, ss, excluded_needing_marker)
    dal.supersede_by_threats(sess, m.Scoped_Threat, sid, ss, excluded_needing_marker)
    sess.execute(insert(m.Scoped_Threat), [
        _build_scoped_threat_row(scoped_id, sid, tenant, ss, sc, entity_id, user_id)
        for sc, scoped_id, _t in pairs if sc.threat_id in excluded_needing_marker])


def _begin_full_run_attempt(sess: Session, sid: str, ss: int, tenant: str,
                            entity_id: str | None, user_id: str | None,
                            pairs: list, epoch: int) -> set[str]:
    if epoch != _EPOCH:
        raise ValueError(
            f"full-run write_scenarios is only valid at the initial epoch {_EPOCH}, got {epoch} — "
            "a regen/next-set hop must pass target_threat_ids and take the targeted branch")
    attempt = dal.stage_attempt_count(sess, sid, ss, SubsystemLevel.SCENARIOS, epoch)
    if attempt == 1:
        dal.supersede(sess, m.Scoped_Threat, sid, ss)
        dal.supersede(sess, m.Threat_Scenario, sid, ss)
        not_selected = [_build_scoped_threat_row(scoped_id, sid, tenant, ss, sc, entity_id, user_id)
                        for sc, scoped_id, _t in pairs if not sc.selected]
        if not_selected:
            sess.execute(insert(m.Scoped_Threat), not_selected)
        sess.commit()
        return set()
    return dal.threats_with_active_scenario(
        sess, sid, ss, {sc.threat_id for sc, _scoped_id, _t in pairs if sc.selected})


def _reconcile_targeted_regen(sess: Session, sid: str, ss: int, tenant: str,
                            entity_id: str | None, user_id: str | None,
                            pairs: list, scenarios: dict, enriched: dict,
                            epoch: int, task_id: str, *, regen_mode: bool,
                            failed_ids: set[str] | None = None,
                            unresolved_targets: dict | None = None) -> bool:
    failed_ids = failed_ids or set()
    generated_ids = {sc.threat_id for sc, scoped_id, _t in pairs if scoped_id in scenarios}
    all_target_ids = {sc.threat_id for sc, _scoped_id, _t in pairs}
    excluded_ids = all_target_ids - generated_ids
    # These are two different situations that used to get lumped together: a target whose
    # generation FAILED (temporary — stays selected, a retry will try again) vs one that
    # genuinely no longer scores high enough to qualify (permanent). Treating a temporary
    # failure as "doesn't qualify anymore" used to send support down the wrong troubleshooting
    # path.
    rescored_ids = excluded_ids - failed_ids
    # Passed back to the caller so it knows which targets to retry. This matters for partial
    # successes too — a batch where some targets succeeded and others didn't used to report
    # plain success with no way to tell which ones still need a retry.
    if unresolved_targets is not None:
        unresolved_targets["failed_ids"] = failed_ids
        unresolved_targets["rescored_ids"] = rescored_ids
    if rescored_ids:
        log.warning("regen.target_no_longer_selected", session_id=sid, subsystem=ss,
                    threat_ids=sorted(rescored_ids))
    if failed_ids:
        log.warning("regen.target_generation_failed", session_id=sid, subsystem=ss,
                    threat_ids=sorted(failed_ids))

    if not regen_mode:
        _mark_next_set_targets_rescored_out(sess, sid, ss, pairs, excluded_ids, tenant, entity_id, user_id)

    if not generated_ids:
        if not dal.finish_stage(sess, sid, ss, SubsystemLevel.SCENARIOS, StageStatus.AWAITING_DECISION, epoch, task_id):
            sess.rollback()
            log.warning("stage.claim_lost", session_id=sid, subsystem=ss, stage="SCENARIOS", epoch=epoch)
            return False
        sess.commit()
        if failed_ids:
            # A generation failure always takes priority in the error message: if anything
            # failed, we say so and make it retryable, instead of showing one of the more
            # final-sounding messages below.
            raise dal.RegenerateConflict(
                f"scenario generation failed for {len(failed_ids)} threat(s); they remain "
                "selected and re-servable — retrying the same action repeats them",
                reason="generation_failed")
        if not pairs:
            raise dal.RegenerateConflict(
                "no unserved threats remain for this asset", reason="no_new_threats_found")
        raise dal.RegenerateConflict(
            f"threat(s) no longer meet the scoping cutoff and cannot be regenerated: {sorted(rescored_ids)}",
            reason="new_threat_did_not_qualify")

    generated_pairs = [(sc, scoped_id, t) for sc, scoped_id, t in pairs if scoped_id in scenarios]
    if regen_mode:
        dal.supersede_scoped_rows(sess, [t.scoped_threat_id for _sc, _scoped_id, t in generated_pairs])
    else:
        old_scoped_ids = dal.active_scoped_threat_ids(sess, sid, ss, generated_ids)
        dal.supersede_by_threats(sess, m.Scoped_Threat, sid, ss, generated_ids)
        dal.supersede_by_scoped_threats(sess, sid, ss, old_scoped_ids)
    scoped_rows = []
    output_rows = []
    for sc, scoped_id, target in pairs:
        if sc.threat_id in excluded_ids:
            continue
        if regen_mode and scoped_id not in scenarios:
            continue
        scoped_rows.append(_build_scoped_threat_row(scoped_id, sid, tenant, ss, sc, entity_id, user_id))
        if scoped_id not in scenarios:
            continue
        scenario, report, span = scenarios[scoped_id]
        number = target.scenario_number if target is not None else 1
        output_rows.append(_build_scenario_output_row(scoped_id, sid, tenant, ss, scenario, report, epoch,
                                                    entity_id, user_id, enriched.get(sc.threat_id, {}),
                                                    scenario_number=number, source="generated",
                                                    span=span))
    if scoped_rows:
        sess.execute(insert(m.Scoped_Threat), scoped_rows)
    if output_rows:
        seen_keys: set[tuple[str, int]] = set()
        deduped_output_rows = []
        for r in output_rows:
            key = (r["IdentityHash"], r["ScenarioNumber"])
            if key in seen_keys:
                continue
            seen_keys.add(key)
            deduped_output_rows.append(r)
        output_rows = deduped_output_rows
        by_number: dict[int, set[str]] = {}
        for h, number in seen_keys:
            by_number.setdefault(number, set()).add(h)
        retired: dict[tuple[str, int], str] = {}
        for number, hashes in by_number.items():
            for h, old_id in dal.supersede_by_identity_hashes(
                    sess, sid, ss, hashes, scenario_number=number).items():
                retired[(h, number)] = old_id
        for r in output_rows:
            r["ReplacesScenarioID"] = retired.get((r["IdentityHash"], r["ScenarioNumber"]))
    if output_rows:
        sess.execute(insert(m.Threat_Scenario), output_rows)
    return True


def _build_work_items(scoped_all: list[scoping.Scored],
                    target_threat_ids: set[str] | None,
                    regen_targets: dict[str, RegenTarget] | None,
                    ) -> tuple[list[tuple], int]:
    pairs: list[tuple[scoping.Scored, str, RegenTarget | None]]
    if regen_targets is not None:
        by_threat_targets: dict[str, list[RegenTarget]] = {}
        for t in regen_targets.values():
            by_threat_targets.setdefault(t.threat_id, []).append(t)
        pairs = [(sc, guid(), t)
                for sc in scoped_all if sc.threat_id in by_threat_targets
                for t in sorted(by_threat_targets[sc.threat_id], key=lambda t: t.scenario_number)]
    elif target_threat_ids is not None:
        pairs = [(sc, guid(), None) for sc in scoped_all if sc.threat_id in target_threat_ids]
    else:
        pairs = [(sc, guid(), None) for sc in scoped_all]
    scoped_threat_count = len({sc.threat_id for sc, _scoped_id, _t in pairs})

    return pairs, scoped_threat_count



def _prepare_scenario_batch(sess: Session, sid: str, ss: int, scenario_session: dict,
                            subsystems: list[dict], asset_context: dict, threats: list[dict],
                            target_threat_ids: set[str] | None,
                            regen_targets: dict[str, RegenTarget] | None,
                            targeted: bool) -> _ScenarioBatch:
    base_ctx = prompts.build_base_context(scenario_session["AssetName"], asset_context, subsystems)

    tn = tuning.from_session(scenario_session)  # tuning settings frozen at session start, not live config
    top_n = get_settings().scoping_top_n  # not session-tunable: None means let coverage decide
    if top_n is not None:
        top_n = min(top_n, tn.max_threats_per_asset)
    with trace_step("SCORING", sid, threats=len(threats),
                    score_threshold=tn.scoping_score_threshold, base_score=tn.base_score) as _t:
        scoped_all = scoping.score_threats(threats,
                                        score_threshold=tn.scoping_score_threshold,
                                        base_score=tn.base_score)
        _t.result(scored=scoped_all)
    enriched = {t["threat_id"]: t for t in threats}
    deduped = _select_unique_top_n(scoped_all, enriched, top_n) if not targeted else 0
    pairs, scoped_count = _build_work_items(scoped_all, target_threat_ids, regen_targets)
    entry_vocab, ambiguous = prompts.entry_point_vocabulary(
        subsystems, scenario_session["AssetName"])
    if ambiguous:
        log.warning("scenario.entry_points_ambiguous", session_id=sid, subsystem=ss,
                    labels=ambiguous)
    if not entry_vocab:
        # This is a WARNING, not just info, because it silently limits every threat in the
        # session to exactly one scenario each. Everything downstream still reports "ok" —
        # validation only checks the narrative fields, not entry points — so without this log
        # line, a session that generated an eighth of its intended output would look
        # completely normal. The count is also saved in the scoping_complete audit row so
        # it isn't lost.
        log.warning("scenario.entry_points_unavailable", session_id=sid, subsystem=ss,
                    subsystems=len(subsystems))
    fold = _fold_scenario_rows(dal.active_scenario_rows(sess, sid, ss))
    intel_terms = _intel_vocabulary(sess, subsystems, asset_context)
    technique_labels = _technique_asset_labels(sess, subsystems, asset_context)
    return _ScenarioBatch(base_ctx, enriched, deduped, pairs, scoped_count, fold, entry_vocab,
                        intel_terms, technique_labels)


def _retire_prior_card(sess: Session, sid: str, ss: int, info: dict) -> str | None:
    identity = dal.identity_hash(sid, ss, info)
    return dal.supersede_by_identity_hashes(sess, sid, ss, {identity}, scenario_number=1).get(identity)


def _persist_full_run_failure(sess: Session, sid: str, ss: int, tenant: str, entity_id: str | None,
                            user_id: str | None, sc, scoped_id: str, info: dict,
                            client_msg: str, epoch: int, span: tuple[datetime, datetime]) -> None:
    retired_card = _retire_prior_card(sess, sid, ss, info)
    dal.supersede_by_threats(sess, m.Scoped_Threat, sid, ss, {sc.threat_id})
    sess.execute(insert(m.Scoped_Threat),
                [_build_scoped_threat_row(scoped_id, sid, tenant, ss, sc, entity_id, user_id)])
    sess.execute(insert(m.Threat_Scenario),
                [_build_error_output_row(scoped_id, sid, tenant, ss, client_msg, epoch,
                                        entity_id, user_id, info, replaces_scenario_id=retired_card,
                                        span=span)])
    sess.commit()


def _persist_full_run_scenario(sess: Session, sid: str, ss: int, tenant: str, entity_id: str | None,
                            user_id: str | None, sc, scoped_id: str, info: dict,
                            scenario: dict, report: dict, epoch: int, *,
                            span: tuple[datetime, datetime], source: str = "generated") -> None:
    retired_card = _retire_prior_card(sess, sid, ss, info)
    # Same as _persist_full_run_failure: retire any existing active Scoped_Threat row for this
    # threat before inserting a new one. This matters on a Celery retry — if attempt 1 failed
    # after creating a scoped row, attempt 2 would otherwise create a second active row for
    # the same threat, silently breaking the "one active row per threat" rule.
    dal.supersede_by_threats(sess, m.Scoped_Threat, sid, ss, {sc.threat_id})
    sess.execute(insert(m.Scoped_Threat),
                [_build_scoped_threat_row(scoped_id, sid, tenant, ss, sc, entity_id, user_id)])
    sess.execute(insert(m.Threat_Scenario),
                [_build_scenario_output_row(scoped_id, sid, tenant, ss, scenario, report, epoch,
                                            entity_id, user_id, info, replaces_scenario_id=retired_card,
                                            source=source, span=span)])
    sess.commit()


def _generate_scenario_batch(sess: Session, scenario_session: dict, base_ctx: dict, work: list,
                            enriched: dict, llm: LLMClient, task_id: str, epoch: int,
                            per_item: dict, session_factory) -> list[tuple]:
    """Generate every scenario in `work`, returning
    (scoped_id, result_or_None, exc_or_None, (started, finished)) in the SAME order - the caller
    persists sequentially, so ordering, ScenarioNumber and determinism are untouched by how the
    calls were dispatched. The span is ALWAYS present: `started` is taken before the try, so a
    failure is timed exactly like a success (see _stamp_generation_span).

    These calls are independent, so running them one at a time made a session's ~10 scenarios
    take ~10x one call for no reason. Same tokens either way; only wall-clock changes.

    EACH CONCURRENT ITEM GETS ITS OWN DB SESSION. _ask_ai commits Prompt_Log rows and renews
    the stage lease mid-call, and a SQLAlchemy Session is not safe to share across greenlets -
    sharing one here would interleave those commits into each other's transactions. The
    caller's `sess` stays untouched until the sequential persist pass.

    Falls back to the caller's session, strictly sequentially, when there is nothing to gain
    (one item, concurrency 1) or nothing to open sessions with (session_factory=None - the
    shape every existing test uses, so their in-memory SQLite session is never bypassed).

    # ponytail: ThreadPoolExecutor, not a new abstraction - llm.rerank_many already runs this
    # exact pattern under the same gevent worker, where threads are greenlets.
    """
    sid = scenario_session["SessionID"]
    concurrency = min(get_settings().scenario_generation_concurrency, len(work))
    if session_factory is None or concurrency <= 1:
        out: list[tuple] = []
        for sc, scoped_id, _target in work:
            started = now()                # ABOVE the try: a failure still gets its span
            try:
                with trace_step("SCENARIO", sid, correlation_id=scoped_id,
                                threat_id=sc.threat_id) as _t:
                    result = _generate_one_scenario(
                        sess, scenario_session, base_ctx, sc, enriched, llm, task_id, epoch,
                        **per_item[scoped_id], correlation_id=scoped_id)
                    span = _stamp_generation_span(started, _t)
                out.append((scoped_id, result, None, span))
            except Exception as exc:  # noqa: BLE001 - [R8] captured per item, re-raised by the caller
                out.append((scoped_id, None, exc, (started, now())))
        return out

    from concurrent.futures import ThreadPoolExecutor

    def _one(item):
        sc, scoped_id, _target = item
        started = now()                    # ABOVE the try: a failure still gets its span
        try:
            # Own session, own transaction, closed before the result is handed back - nothing
            # from this greenlet is still open when the caller starts persisting.
            with session_factory() as worker_sess, \
                    trace_step("SCENARIO", sid, correlation_id=scoped_id,
                            threat_id=sc.threat_id) as _t:
                result = _generate_one_scenario(
                    worker_sess, scenario_session, base_ctx, sc, enriched, llm, task_id, epoch,
                    **per_item[scoped_id], correlation_id=scoped_id)
                span = _stamp_generation_span(started, _t)
                return (scoped_id, result, None, span)
        except Exception as exc:  # noqa: BLE001 - [R8] same contract as the sequential branch
            return (scoped_id, None, exc, (started, now()))

    with ThreadPoolExecutor(max_workers=concurrency) as pool:
        return list(pool.map(_one, work))   # map preserves input order


def _flag_same_batch_duplicates(by_scoped: dict, identities: dict, ratio: float) -> None:
    """Flag any scenario in THIS batch that reads as a near-duplicate of one of its siblings.

    The within-batch half of duplicate detection. The cross-ROUND half lives in
    _generate_one_scenario (`cov.others`), which compares against text persisted by EARLIER
    rounds — kept separate so a scenario is checked both against its own batch's siblings and
    against history, not just one or the other.

    Deterministic string work with no model call, so comparing everything against everything
    costs nothing and needs no sampling.
    """
    fresh = [(identities[sc_id], str((res[0] or {}).get("scenario_statement") or ""))
            for sc_id, (res, *_) in by_scoped.items() if res is not None]
    for sc_id, (res, *_) in by_scoped.items():
        if res is None:
            continue
        others = [text for h, text in fresh if h != identities[sc_id]]
        if others:
            _flag_cross_threat_similarity(res[1], res[0], others, ratio)


def _persist_batch_results(sess: Session, scenario_session: dict, work: list, by_scoped: dict,
                           enriched: dict, epoch: int, task_id: str, *, targeted: bool
                           ) -> tuple[list, list[str], set[str], dict, Exception | None, Exception | None]:
    """Persist a generated batch SEQUENTIALLY, in the original order, on the caller's session.

    Returns (provs, failures, failed_ids, scenarios, first_failure, slot_unavailable) for
    write_scenarios to act on. Lifted out of write_scenarios unchanged so that the per-item
    contract - including the span every item now carries - lives in one function of readable
    size; the stage transition (finish_stage) and the control-mapping tail stay in the caller.
    """
    sid, ss, tenant = scenario_session["SessionID"], ASSET_UNIT_ID, scenario_session["TenantID"]
    entity_id, user_id = scenario_session["EntityID"], scenario_session.get("UserID")
    provs: list[Provenance | None] = []
    scenarios: dict[str, tuple[dict, dict, tuple[datetime, datetime]]] = {}
    failures: list[str] = []
    failed_ids: set[str] = set()  # threat ids whose GENERATION failed - never "rescored out"
    first_failure: Exception | None = None
    slot_unavailable: Exception | None = None
    for sc, scoped_id, _target in work:
        result, exc, span = by_scoped[scoped_id]
        if exc is not None:
            if isinstance(exc, LLMSlotUnavailable):
                # Not a scenario failure: no capacity right now. Remembered and raised AFTER
                # the successes are committed, so a starved call cannot throw away work that
                # was already generated and already billed. Celery retries the stage and
                # _begin_full_run_attempt's already_done skips whatever landed.
                slot_unavailable = slot_unavailable or exc
                continue
            sess.rollback()
            first_failure = first_failure or exc
            failed_ids.add(sc.threat_id)
            client_msg = _failure_client_message(exc)
            failures.append(f"{enriched.get(sc.threat_id, {}).get('threat_name') or sc.threat_id}: {client_msg}")
            log.warning("scenario.generation_failed", session_id=sid, subsystem=ss,
                        threat_id=sc.threat_id, error=repr(exc))
            if not targeted:
                _persist_full_run_failure(sess, sid, ss, tenant, entity_id, user_id, sc, scoped_id,
                                        enriched.get(sc.threat_id, {}), client_msg, epoch, span)
            continue
        scenario, report, prov = result
        provs.append(prov)
        if not targeted:
            if not dal.renew_lease(sess, sid, ss, SubsystemLevel.SCENARIOS, epoch, task_id):
                sess.rollback()
                log.warning("stage.claim_lost_midbatch", session_id=sid, subsystem=ss,
                            stage="SCENARIOS", epoch=epoch, committed=len(provs) - 1)
                break
            _persist_full_run_scenario(sess, sid, ss, tenant, entity_id, user_id, sc, scoped_id,
                                    enriched.get(sc.threat_id, {}), scenario, report, epoch,
                                    span=span, source="generated")
        else:
            scenarios[scoped_id] = (scenario, report, span)
    return provs, failures, failed_ids, scenarios, first_failure, slot_unavailable


def write_scenarios(sess: Session, scenario_session: dict, subsystems: list[dict], asset_context: dict, threats: list[dict],
                llm: LLMClient, task_id: str,
                epoch: int = _EPOCH, target_threat_ids: set[str] | None = None,
                *, require_lock: bool = False,
                regen_targets: dict[str, RegenTarget] | None = None,
                on_before_commit: Callable[[list[Provenance | None]], None] | None = None,
                unresolved_targets: dict | None = None,
                session_factory: Callable[[], Any] | None = None) -> list[Provenance | None]:

    sid, ss, tenant = scenario_session["SessionID"], ASSET_UNIT_ID, scenario_session["TenantID"]
    entity_id, user_id = scenario_session["EntityID"], scenario_session.get("UserID")
    if require_lock and not dal.holds_lock(sess, sid, ss, task_id):
        log.warning("subsystem.lock_lost_before_scenarios", session_id=sid, subsystem=ss)
        return []
    if not dal.claim_stage(sess, sid, ss, SubsystemLevel.SCENARIOS, epoch, task_id):
        return []
    sess.commit()
    _send_live_update(sid, SSEEventType.stage_started, ss, SubsystemLevel.SCENARIOS, StageStatus.RUNNING, epoch)

    targeted = target_threat_ids is not None or regen_targets is not None
    batch = _prepare_scenario_batch(sess, sid, ss, scenario_session, subsystems, asset_context, threats,
                                    target_threat_ids, regen_targets, targeted)
    base_ctx, enriched, deduped = batch.base_ctx, batch.enriched, batch.deduped
    pairs, scoped_threat_count = batch.pairs, batch.scoped_count
    siblings_by_hash, entry_vocab = batch.fold.siblings_by_hash, batch.entry_vocab
    cross_pairs = list(batch.fold.cross_pairs)

    already_done: set[str] = set()
    if not targeted:
        already_done = _begin_full_run_attempt(sess, sid, ss, tenant, entity_id, user_id, pairs, epoch)
    work = [(sc, scoped_id, target) for sc, scoped_id, target in pairs
            if sc.selected and sc.threat_id not in already_done]
    identities = {scoped_id: dal.identity_hash(sid, ss, enriched.get(sc.threat_id, {}))
                for sc, scoped_id, _t in work}
    per_item: dict[str, dict] = {}
    for _sc, scoped_id, target in work:
        sibling_texts = None
        if target is not None and target.identity_hash:
            sibling_texts = [(number, statement)
                            for scenario_id, number, statement in siblings_by_hash.get(target.identity_hash, [])
                            if scenario_id != target.scenario_id] or None
        per_item[scoped_id] = {
            "sibling_texts": sibling_texts,
            # others=PRE-EXISTING scenarios only. The same-batch comparison used to happen
            # here by appending to cross_pairs as the loop went, which meant scenario 1 was
            # never compared against scenario 10 - the first one generated was checked
            # against nothing. It now runs as one pass over the WHOLE batch below, which is
            # both order-independent and strictly more thorough.
            "coverage": _Coverage(vocab=entry_vocab,
                                frozen=batch.fold.frozen_by_hash.get(identities[scoped_id]),
                                others=[s for h, s in cross_pairs
                                        if h != identities[scoped_id]] or None,
                                intel_terms=batch.intel_terms,
                                technique_labels=batch.technique_labels),
        }
        # correlation_id is passed as a LITERAL keyword at each call site, never through this
        # dict: scripts/test_pipeline_guards.py verifies the stamp by reading the AST, and a
        # value hidden inside **kwargs would silently retire that check.
    generated = _generate_scenario_batch(sess, scenario_session, base_ctx, work, enriched,
                                        llm, task_id, epoch, per_item, session_factory)
    by_scoped = {sc_id: (res, exc, span) for sc_id, res, exc, span in generated}

    ratio = tuning.from_session(scenario_session).sibling_similarity_ratio
    _flag_same_batch_duplicates(by_scoped, identities, ratio)

    provs, failures, failed_ids, scenarios, first_failure, slot_unavailable = _persist_batch_results(
        sess, scenario_session, work, by_scoped, enriched, epoch, task_id, targeted=targeted)

    if failures and not provs and not already_done and first_failure is not None:
        raise first_failure
    if slot_unavailable is not None:
        # Every success is committed by now (_persist_full_run_scenario commits per item), so
        # the retry Celery is about to run resumes instead of regenerating and re-billing.
        log.warning("scenarios.slot_exhausted_midbatch", session_id=sid, subsystem=ss,
                    committed=len(provs))
        raise slot_unavailable

    dal.append_audit(sess, AuditID=guid(), SessionID=sid, TenantID=tenant, EntityID=scenario_session["EntityID"],
                    Stage=WorkflowStage.SCENARIO_GENERATION, SubsystemID=ss,
                    EventType=AuditEventType.scoping_complete,
                    # entry_points: 0 means nothing in this batch could get a second scenario —
                    # the whole session is capped at one per threat. Recorded here (not just
                    # logged) so it's visible later; nothing else in /results shows this.
                    DetailJSON=json.dumps({"scoped": scoped_threat_count, "selected": len(provs),
                                        "deduped": deduped, "entry_points": len(entry_vocab)}))
    log.info("scenarios.deduped", session_id=sid, subsystem=ss, deduped=deduped, kept=len(provs))

    if targeted and not _reconcile_targeted_regen(
            sess, sid, ss, tenant, entity_id, user_id,
            pairs, scenarios, enriched, epoch, task_id,
            regen_mode=regen_targets is not None, failed_ids=failed_ids,
            unresolved_targets=unresolved_targets):
        return []
    partial_error = (f"{len(failures)} of {len(failures) + len(provs)} scenario(s) failed to "
                    f"generate: {'; '.join(failures)}") if failures else None
    if not dal.finish_stage(sess, sid, ss, SubsystemLevel.SCENARIOS, StageStatus.AWAITING_DECISION,
                            epoch, task_id, error=partial_error):
        sess.rollback()
        log.warning("stage.claim_lost", session_id=sid, subsystem=ss, stage="SCENARIOS", epoch=epoch)
        return []
    if on_before_commit is not None:
        on_before_commit(provs)
    sess.commit()
    # AFTER the commit, deliberately — see _finalize_scenario_batch. It used to run above,
    # inside this still-unvalidated transaction, where map_controls' own mid-function commit
    # made a targeted regen's rows permanent and left the `sess.rollback()` above discarding
    # nothing. Nothing is pending here, so that commit can no longer catch anyone else's writes.
    _finalize_scenario_batch(sess, scenario_session, asset_context, subsystems, llm, task_id, epoch)
    _send_live_update(sid, SSEEventType.stage_completed, ss, SubsystemLevel.SCENARIOS, StageStatus.AWAITING_DECISION, epoch)
    log.info("stage.complete", session_id=sid, subsystem=ss, stage="SCENARIOS", scenarios=len(provs))
    return provs


def _finalize_scenario_batch(sess: Session, scenario_session: dict, asset_context: dict,
                            subsystems: list[dict], llm: LLMClient, task_id: str,
                            epoch: int) -> None:
    """Step-4 control mapping, the tail of a scenario batch.

    ALWAYS durable, and ALWAYS called after the caller has committed — those are one fix, not two.

    THE BUG. map_controls commits mid-function (control_mapping.py) to end its lease transaction
    before the slow rerank, and a commit cannot distinguish its own write from whatever else the
    caller still has pending. While this ran INSIDE the caller's transaction, a targeted regen
    passed durable=False to protect its unvalidated rows — and that mid-function commit made them
    permanent regardless, so `sess.rollback()` on a lost finish_stage claim discarded NOTHING. A
    regenerate that lost its claim left rows behind that the code believed it had thrown away.

    Two smaller-looking fixes were rejected on evidence. Gating that commit on `durable` only
    moves the damage: its comment states a real requirement, and holding a write transaction open
    across the rerank keeps row locks for seconds. Moving the lease to its own session deadlocks:
    write_scenarios renews the SAME stage row on `sess` mid-loop without committing, so a second
    connection blocks on the caller's own lock and hangs the worker.

    Running after the commit removes the conflict rather than choosing which side to damage —
    there is nothing pending left for that commit to catch, on either path, which is why `durable`
    stopped being a parameter here. If the worker dies in the gap, the row keeps ControlsMappedAt
    NULL and tsg.map_controls_sweep maps it within one tick. That is what makes this reordering
    safe now and would NOT have been safe before the sweep existed.
    """
    control_mapping.map_controls(sess, scenario_session, asset_context, subsystems, llm,
                                ASSET_UNIT_ID, task_id, epoch, durable=True)


def write_variant_scenarios(sess: Session, scenario_session: dict, subsystem_id: int,
                            subsystems: list[dict], asset_context: dict, llm: LLMClient,
                            task_id: str, epoch: int, max_variants: int,
                            exclude_threat_ids: set[str] | None = None) -> int:
    from sqlalchemy.exc import IntegrityError

    sid, ss, tenant = scenario_session["SessionID"], subsystem_id, scenario_session["TenantID"]
    entity_id, user_id = scenario_session["EntityID"], scenario_session.get("UserID")
    fold = _fold_scenario_rows(dal.active_scenario_rows(sess, sid, ss))
    eligible = dal.variant_eligible_primaries(
        sess, sid, max_variants, rows=fold.rows,
        attempt_slack=tuning.from_session(scenario_session).coverage_attempt_slack,
        exclude_threat_ids=exclude_threat_ids)
    if not eligible:
        log.info("variant.coverage_exhausted", session_id=sid, subsystem=ss)
        return 0
    entry_vocab, ambiguous = prompts.entry_point_vocabulary(
        subsystems, scenario_session["AssetName"])
    if ambiguous:
        log.warning("variant.entry_points_ambiguous", session_id=sid, subsystem=ss, labels=ambiguous)
    # Variants skip _prepare_scenario_batch, so intel terms are resolved here instead using
    # the same shared helper — otherwise every variant would silently get no intel block.
    intel_terms = _intel_vocabulary(sess, subsystems, asset_context)
    technique_labels = _technique_asset_labels(sess, subsystems, asset_context)
    threats = dal.active_threats(sess, sid, ss)
    enriched = {t["threat_id"]: t for t in threats}
    base_ctx = prompts.build_base_context(scenario_session["AssetName"], asset_context, subsystems)
    siblings_by_hash = {h: [(n, s) for _oid, n, s in v]
                        for h, v in fold.siblings_by_hash.items()}
    cross_pairs = list(fold.cross_pairs)

    created = 0
    for item in eligible:
        info = enriched.get(item["threat_id"])
        if not info:
            continue
        try:
            factors = json.loads(item["factors_json"]) if item["factors_json"] else []
        except (TypeError, ValueError):
            factors = []
        sel = item.get("selection_kind")
        sc = scoping.Scored(threat_id=item["threat_id"], score=item["score"] or 0.0,
                            rank=item["scope_rank"] or 0, selected=True,
                            reason=item["reason"] or "",
                            # older primaries (before this column existed) have NULL here — kept as None, never guessed
                            selection=SelectionReason(sel) if sel else None,
                            factors=factors)
        # Minted BEFORE the call, not after it, so the generation's Prompt_Log rows can carry it.
        # Left unused on the break/continue paths below — guid() is pure, so a discarded id is free.
        # This hoist and the correlation_id argument below are one change: passing the id while it
        # is still minted after the call would stamp receipts with the PREVIOUS card's id, which is
        # worse than NULL because a wrong id reads as an answer.
        scoped_id = guid()
        try:
            with trace_step("SCENARIO", sid, correlation_id=scoped_id,
                            variant_number=item["next_number"]) as _t:
                _started = now()
                scenario, report, _prov = _generate_one_scenario(
                    sess, scenario_session, base_ctx, sc, enriched, llm, task_id, epoch,
                    sibling_texts=siblings_by_hash.get(item["identity_hash"]) or None,
                    coverage=_Coverage(
                        vocab=entry_vocab,
                        frozen=fold.frozen_by_hash.get(item["identity_hash"]),
                        others=[s for h, s in cross_pairs if h != item["identity_hash"]] or None,
                        intel_terms=intel_terms,
                        technique_labels=technique_labels),
                    correlation_id=scoped_id)
                span = _stamp_generation_span(_started, _t)
        except LLMSlotUnavailable:
            sess.rollback()
            log.warning("variant.slots_exhausted", session_id=sid, subsystem=ss,
                        created=created, remaining=len(eligible) - created)
            break
        except Exception as exc:  # noqa: BLE001 — [R8] one variant's failure must not kill the batch
            sess.rollback()
            log.warning("variant.generation_failed", session_id=sid, subsystem=ss,
                        threat_id=item["threat_id"], error=repr(exc))
            continue
        try:
            sess.execute(insert(m.Scoped_Threat),
                        [_build_scoped_threat_row(scoped_id, sid, tenant, ss, sc, entity_id, user_id)])
            sess.execute(insert(m.Threat_Scenario),
                        [_build_scenario_output_row(scoped_id, sid, tenant, ss, scenario, report, epoch,
                                                    entity_id, user_id, info,
                                                    scenario_number=item["next_number"],
                                                    span=span)])
            sess.commit()
        except IntegrityError:
            sess.rollback()
            log.info("variant.race_lost", session_id=sid, subsystem=ss, threat_id=item["threat_id"],
                    scenario_number=item["next_number"])
            continue
        cross_pairs.append((item["identity_hash"], str(scenario.get("scenario_statement") or "")))
        created += 1
    if created:
        try:
            _finalize_scenario_batch(sess, scenario_session, asset_context, subsystems, llm, task_id, epoch)
            sess.commit()
        except Exception as exc:  # noqa: BLE001 — [R8] finalize is best-effort; scenarios already committed
            sess.rollback()
            log.warning("variant.finalize_failed", session_id=sid, subsystem=ss,
                        created=created, error=repr(exc))
    return created


def _classify_llm_failure(exc: Exception) -> tuple[str, str]:
    """One shared classification of a terminal LLM/stage failure: a stable token a caller can
    switch on ('guardrail' | 'parse' | 'generic') plus the client-safe message. The TOKEN is
    the contract — treatment._classify_failure maps it to a TreatmentOutcomeReason — so no
    caller anywhere matches the English text (a rewording must never silently change a wire
    reason)."""
    if isinstance(exc, validation.LLMResponseParseError):
        # A SENTENCE, not repr(exc): this string is published to tenant clients (the stage
        # ErrorMessage column and the SSE error event), and a Python exception repr is an
        # internal detail — the same reason treatment._classify_failure words its own parse
        # case in prose. The repr is still recorded server-side by _record_failure's log line.
        return "parse", "the model's reply was not usable JSON"
    if isinstance(exc, LLMRefusal):
        # Structured Outputs' refusal shape — a safety refusal, so the guardrail token: the one
        # class a client must NOT auto-retry unchanged (treatment -> content_blocked).
        return "guardrail", "content blocked by the model's safety refusal"
    if isinstance(exc, LLMResponseTruncated):
        # A budget failure, named as one. Generic token: treatment reports generation_failed,
        # documented "retryable as-is" — true for a stochastic cut (a regenerate recovers).
        return "generic", "the model ran out of output budget before finishing its reply"
    try:
        from litellm.exceptions import RejectedRequestError
    except ImportError:
        return "generic", "stage processing failed"
    if isinstance(exc, RejectedRequestError):
        return "guardrail", "content blocked by a configured safety guardrail"
    return "generic", "stage processing failed"


def _failure_client_message(exc: Exception) -> str:
    return _classify_llm_failure(exc)[1]


def _record_failure(sess: Session, scenario_session: dict, subsystem_id: int, exc: Exception,
                    epoch: int = _EPOCH, extra: dict | None = None) -> None:
    sess.rollback()
    sid = scenario_session["SessionID"]
    client_msg = _failure_client_message(exc)
    _now = now()   # one instant for UpdatedAt and FinishedAt, as claim_stage/finish_stage do
    sess.execute(
        update(m.Subsystem_Stage_State)
        .where(m.Subsystem_Stage_State.SessionID == sid,
            m.Subsystem_Stage_State.SubsystemID == subsystem_id,
            m.Subsystem_Stage_State.Level.in_(list(_WORK_LEVELS)),
            m.Subsystem_Stage_State.GenerationEpoch == epoch,
            m.Subsystem_Stage_State.Status.in_([StageStatus.IDLE, StageStatus.RUNNING]))
        # Runs in the worker at the moment of failure, so FinishedAt here is exact - unlike the
        # reaper's HeartbeatAt lower bound. Every terminal write stamps an end; the static test in
        # test_step_timings refuses one that does not.
        .values(Status=StageStatus.ERROR, ErrorMessage=client_msg, LeaseExpiresAt=None,
                UpdatedAt=_now, FinishedAt=_now)
    )
    detail = {"error": client_msg, "subsystem_id": subsystem_id}
    if extra:
        detail.update(extra)
    dal.append_audit(sess, AuditID=guid(), SessionID=sid, TenantID=scenario_session["TenantID"], EntityID=scenario_session["EntityID"],
                    SubsystemID=subsystem_id, EventType=AuditEventType.stage_error,
                    DetailJSON=json.dumps(detail))
    sess.commit()
    # Item 27: explicit "scope" instead of leaving the client to infer it from whether
    # subsystem_id is present — see the typed ErrorEvent model (schemas.py) for the full contract.
    bus.publish(sid, {"type": str(SSEEventType.error), "session_id": sid, "subsystem_id": subsystem_id,
                    "scope": "stage", "message": client_msg, "generation_epoch": epoch, "ts": now().isoformat()})
    # exc_info: this is the TERMINAL sink for every stage failure (4 call sites) and the ONLY
    # surface that keeps the original — the DB ErrorMessage, the stage_error audit row and the
    # SSE event all carry _failure_client_message(exc), which collapses anything that is not a
    # parse/guardrail case to "stage processing failed". Without the traceback a KeyError from
    # ~20 frames down is unattributable. exc, not True: the raise site is a caller, not here.
    log.error("stage.error", session_id=sid, subsystem=subsystem_id, error=repr(exc),
            exc_info=exc)


def decide_session_outcome(sess: Session, scenario_session: dict) -> str | None:
    sid = scenario_session["SessionID"]
    statuses = [str(r["Status"]) for r in dal.stage_rows(sess, sid)]
    if not statuses or any(s in (StageStatus.IDLE, StageStatus.RUNNING) for s in statuses):
        return None
    if dal.has_active_scenarios(sess, sid):
        dal.revive_errored_scenarios_to_review(sess, sid)
        statuses = [str(r["Status"]) for r in dal.stage_rows(sess, sid)]
    # Both branches below LOG a declined CAS instead of returning None silently. A finalize that
    # quietly does nothing is how a session ends up stranded outside REVIEW with every stage row
    # terminal and nothing in the logs to say why — the exact dead end that made the abandoned-run
    # bug invisible until someone read the DB by hand. `rowcount != 1` means the row moved under us
    # (already at REVIEW, or no longer `active`): usually benign, occasionally the only breadcrumb
    # there is. Either way it must be visible.
    if any(s == StageStatus.AWAITING_DECISION for s in statuses):
        if _send_to_review(sess, scenario_session):
            return "review"
        log.warning("finalize.send_to_review_declined", session_id=sid, statuses=statuses,
                    session_status=str(scenario_session.get("SessionStatus")),
                    current_stage=str(scenario_session.get("CurrentStage")),
                    note="CAS matched no row — session already at REVIEW, or no longer active")
        return None
    if any(s == StageStatus.ERROR for s in statuses):
        if _mark_session_failed(sess, scenario_session):
            return "cancelled"
        log.warning("finalize.mark_failed_declined", session_id=sid, statuses=statuses,
                    session_status=str(scenario_session.get("SessionStatus")),
                    current_stage=str(scenario_session.get("CurrentStage")),
                    note="CAS matched no row — session already terminal, or no longer active")
        return None
    log.warning("finalize.no_terminal_state", session_id=sid, statuses=statuses)
    return None


# KNOWN LIMITATION: session_entered_review's generation_epoch always reports the module-level
# _EPOCH default (1), even when a regenerate (epoch > 1) is what actually drove the session back
# into REVIEW via decide_session_outcome. Scenario_Session has no session-level GenerationEpoch
# column — epoch lives per subsystem/stage on Subsystem_Stage_State only — so there is no single
# "current epoch" value decide_session_outcome can read and thread through without adding an epoch
# parameter to decide_session_outcome itself and updating every caller (cascade.py's several call
# sites, reaper.py, sessions.py). Not fixed here; the durable, correct-epoch signal for a regen is
# progress.last_regen.epoch (see GET /v1/sessions/{id}), not this event's generation_epoch. See
# docs/SSE_SESSION_PROGRESS_CONTRACT_GUIDE.md §4.7.
def _send_to_review(sess: Session, scenario_session: dict, epoch: int = _EPOCH) -> bool:
    """Generation is finished: park at the review barrier AND end the session.

    The session's own lifecycle is "a generation request", not "a review workstream" — it ends
    when generation ends, which is what releases the asset (UX_Session_ActiveAsset is filtered on
    SessionStatus='active'). Each scenario then carries its own pending -> accepted/rejected
    lifecycle for as long as the reviewer needs, with no session left holding the asset open.

    CurrentStage/StageStatus stay REVIEW/AWAITING_DECISION: they describe the EXECUTION, and
    "awaiting a human decision" is still true. review_gate_reason tests that pair BEFORE it tests
    SessionStatus, so accept and regenerate keep passing the gate on a completed session — that
    ordering is load-bearing, not incidental.

    CompletedAt uses COALESCE so a next-set run (which re-reserves the session and comes back
    through here) never rewrites when generation first finished."""
    sid = scenario_session["SessionID"]
    res = execute_dml(
        sess,
        update(m.Scenario_Session)
        .where(m.Scenario_Session.SessionID == sid,
            m.Scenario_Session.SessionStatus == SessionStatus.active,
            m.Scenario_Session.CurrentStage != WorkflowStage.REVIEW)
        .values(CurrentStage=WorkflowStage.REVIEW, StageStatus=StageStatus.AWAITING_DECISION,
                SessionStatus=SessionStatus.completed,
                CompletedAt=func.coalesce(m.Scenario_Session.CompletedAt, now()), UpdatedAt=now())
    )
    if res.rowcount != 1:
        return False
    dal.append_audit(sess, AuditID=guid(), SessionID=sid, TenantID=scenario_session["TenantID"],
                    EntityID=scenario_session["EntityID"], Stage=WorkflowStage.REVIEW, EventType=AuditEventType.entered_review)
    sess.commit()
    bus.publish(sid, {"type": str(SSEEventType.session_entered_review), "session_id": sid,
                    "status": str(StageStatus.AWAITING_DECISION), "generation_epoch": epoch, "ts": now().isoformat()})
    log.info("pipeline.entered_review", session_id=sid)
    return True


def _mark_session_failed(sess: Session, scenario_session: dict) -> bool:
    sid = scenario_session["SessionID"]
    res = execute_dml(
        sess,
        update(m.Scenario_Session)
        .where(m.Scenario_Session.SessionID == sid,
            m.Scenario_Session.SessionStatus == SessionStatus.active,
            m.Scenario_Session.CurrentStage != WorkflowStage.REVIEW)
        .values(SessionStatus=SessionStatus.cancelled, CurrentStage=WorkflowStage.CANCELLED,
                StageStatus=StageStatus.CANCELLED, UpdatedAt=now())
    )
    if res.rowcount != 1:
        return False
    dal.append_audit(sess, AuditID=guid(), SessionID=sid, TenantID=scenario_session["TenantID"], EntityID=scenario_session["EntityID"],
                    EventType=AuditEventType.session_cancelled, DetailJSON=json.dumps({"reason": "all subsystems failed"}))
    sess.commit()
    # Item 27: explicit "scope" — see the typed ErrorEvent model (schemas.py) for the full contract.
    bus.publish(sid, {"type": str(SSEEventType.error), "session_id": sid, "scope": "session",
                    "message": "session failed: all subsystems errored", "ts": now().isoformat()})
    log.warning("pipeline.failed", session_id=sid)
    return True


def _announce_generation_started(sess: Session, scenario_session: dict, subsystem_id: int, epoch: int = _EPOCH) -> None:
    if not dal.subsystem_has_pending_work(sess, scenario_session["SessionID"], subsystem_id):
        return
    sid = scenario_session["SessionID"]
    dal.append_audit(sess, AuditID=guid(), SessionID=sid, TenantID=scenario_session["TenantID"],
                    EntityID=scenario_session["EntityID"], SubsystemID=subsystem_id,
                    EventType=AuditEventType.subsystem_advanced,
                    DetailJSON=json.dumps({"subsystem_id": subsystem_id}))
    sess.commit()
    bus.publish(sid, {"type": str(SSEEventType.subsystem_started), "session_id": sid,
                    "subsystem_id": subsystem_id, "generation_epoch": epoch, "ts": now().isoformat()})


def _summarize_generation(sub_id: int, prov_i: Provenance | None, scen_provs: list[Provenance | None]) -> dict:
    return {
        "subsystem_id": sub_id, "identify_provenance": _summarize_ai_call(prov_i),
        "scenario_provenances": [_summarize_ai_call(p) for p in scen_provs],
        "scenario_count": len(scen_provs),
    }


def _process_all_supporting_systems(sess: Session, session_id: str, llm: LLMClient, task_id: str) -> None:
    row = dal.load_session(sess, session_id)
    if row is None:
        return
    scenario_session = dict(row)
    if scenario_session["CurrentStage"] == WorkflowStage.REVIEW:
        log.warning("pipeline.refused_review_session", session_id=session_id, task_id=task_id)
        return
    subsystems = json.loads(scenario_session["SubsystemsJSON"])
    asset_context = json.loads(scenario_session.get("AssetContextJSON") or "{}")
    log.info("pipeline.start", session_id=session_id, subsystems=len(subsystems), task_id=task_id)
    if dal.acquire_lock(sess, session_id, ASSET_UNIT_ID, task_id):
        sess.commit()
        try:
            categories = dal.active_category_names(sess)
            _announce_generation_started(sess, scenario_session, ASSET_UNIT_ID)
            threats, prov_i = find_threats(sess, scenario_session, subsystems, asset_context, llm, task_id,
                                        categories=categories)
            sess.commit()
            threats_stage_done = True
            if not threats:
                threats = dal.active_threats(sess, session_id, ASSET_UNIT_ID)
                threats_stage_done = bool(threats) or dal.stage_completed_at_epoch_or_newer(
                    sess, session_id, ASSET_UNIT_ID, SubsystemLevel.THREATS, _EPOCH)
            if threats_stage_done:
                scen_provs = write_scenarios(sess, scenario_session, subsystems, asset_context, threats, llm, task_id,
                                            require_lock=True,
                                            # Only the worker entry point hands over a real
                                            # factory, so ONLY the worker generates in
                                            # parallel — as do regenerate and next-set
                                            # (cascade.py). This comment used to claim the
                                            # targeted paths "arrive with uncommitted rows on
                                            # `sess`" and had to stay sequential. That was FALSE
                                            # at the point it mattered: write_scenarios commits
                                            # immediately after claim_stage, _prepare_scenario_batch
                                            # writes nothing, and the only statement before the
                                            # batch dispatches is an SSE publish — so `sess` is
                                            # clean on EVERY path. The uncommitted rows it meant
                                            # (_reconcile_targeted_regen) are written AFTER
                                            # generation. Tests passing session_factory=None still
                                            # get the sequential branch.
                                            session_factory=db_session)
                dal.append_audit(sess, AuditID=guid(), SessionID=session_id, TenantID=scenario_session["TenantID"],
                                EntityID=scenario_session["EntityID"], Stage=WorkflowStage.SCENARIO_GENERATION,
                                SubsystemID=ASSET_UNIT_ID, EventType=AuditEventType.generation_complete,
                                DetailJSON=json.dumps(_summarize_generation(ASSET_UNIT_ID, prov_i, scen_provs)))
                sess.commit()
            else:
                log.warning("pipeline.threats_not_complete_skipping_scenarios", session_id=session_id, task_id=task_id)
        except LLMSlotUnavailable:
            raise
        except TRANSIENT_INFRA_ERRORS as exc:
            # The infrastructure hiccuped — the work is not wrong. Re-raise for Celery's
            # autoretry (the stage CAS re-claims under the same task id); routing this
            # into _record_failure would CANCEL the whole session over a transient
            # deadlock/connection blip. The `finally` below still releases the lock, and
            # decide_session_outcome is deliberately skipped.
            log_transient_infra_retry(site="run_pipeline.asset_stage",
                                    session_id=session_id, subsystem_id=ASSET_UNIT_ID,
                                    exc=exc)
            # The failed transaction must be cleared BEFORE the finally's release_lock
            # runs SQL — otherwise PendingRollbackError replaces this exception mid-flight
            # and Celery's autoretry (keyed on OperationalError) never fires.
            sess.rollback()
            raise
        except Exception as exc:  # noqa: BLE001 — capture, don't swallow ([R8]); lock must still release in finally
            _record_failure(sess, scenario_session, ASSET_UNIT_ID, exc)
            sess.commit()
        finally:
            if not dal.release_lock(sess, session_id, ASSET_UNIT_ID, task_id):
                log.warning("asset.lock_lost", session_id=session_id, task_id=task_id)
            sess.commit()
    else:
        log.warning("asset.locked", session_id=session_id, session_status=scenario_session["SessionStatus"])

    decide_session_outcome(sess, scenario_session)