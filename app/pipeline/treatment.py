"""Risk Treatment (Mitigate) Plan generation — docs/RISK_TREATMENT_PLAN_SDD.md.

Self-contained module in the control_mapping.py mould: the snapshot builder, output
validation and the worker body all live here; the API layer (app/api/treatment.py) calls the
build half at POST time, the Celery task calls run_treatment_generation.

TSG reads NO risk-module tables: the register's risk data (ratings, level, existing
controls, echo fields) arrives IN the request body and is frozen — together with TSG's own
scenario/asset/threat/mapped-controls context — into InputSnapshotJSON at POST time. The
worker prompts from that snapshot and the GET serves it, so nothing external can skew a
stored plan.

OUTSIDE the stage machinery: accepted scenarios exist only on COMPLETED
sessions, where dal.acquire_lock/claim_stage refuse to run — the Risk_Treatment_Plan row's
own Status column is the state, fenced by the conditional-UPDATE helpers in dal.py
(claim_plan / finish_plan / supersede_active_plan).

The worker body also publishes an advisory SSE refetch hint after each COMMITTED finish
(_publish_plan_result) — the module's only cross-cutting side effect. It is a hint, never a
completion contract; see that function's docstring for the three outcomes that never publish.
"""
from __future__ import annotations

import json
import re
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.enums import (
    ActionPriority,
    AuditEventType,
    ControlCoverage,
    ControlType,
    SSEEventType,
    StageStatus,
    TreatmentGateReason,
    TreatmentOutcomeReason,
    TreatmentStrategy,
    YesNo,
)
from app.core.logging import get_logger
from app.core.security import redact
from app.db import dal
from app.db import models as m
from app.pipeline import grounding, prompts
from app.pipeline import llm as llm_mod
from app.pipeline.llm import LLMClient, LLMSlotUnavailable
from app.pipeline.tasks import ASSET_UNIT_ID, _ask_ai, _classify_llm_failure
from app.pipeline.validation import LLMResponseParseError
from app.sse import bus

log = get_logger(__name__)

# Plan keys the SERVER owns (docs/RISK_TREATMENT_PLAN_SDD.md — reserved-key rule): stamped or
# echoed at finish time, OVERWRITING anything the model emitted under the same name, so AI
# output can never impersonate register data. (controls_to_be_implemented is NOT here — it is
# the AI's own gap-analysis table, so the injector must never touch it.)
_RESERVED_PLAN_KEYS = ("treatment_plan", "risk_identification_date",
                    "risk_owner", "impacted_business_division")

# Per-field cap applied to UI-supplied free text at snapshot time (house analog: intel items
# truncate before entering the prompt). Pydantic max_length bounds reject oversized fields at
# the boundary; this is defense-in-depth for anything that slips a path around them. Lives in
# Settings.treatment_free_text_cap now (default unchanged: 2000).


class TreatmentConflict(Exception):
    """Treatment-plan request refused → HTTP 409 with `details.reason` (TreatmentGateReason).
    Mirrors AcceptConflict's shape: message for the human, reason for the client switch."""

    def __init__(self, message: str, *, reason: TreatmentGateReason | None = None):
        self.reason = str(reason) if reason else None
        super().__init__(message)


class TreatmentPlanInvalid(Exception):
    """The LLM reply parsed as JSON but violates the plan contract structurally (a required
    table missing or not a list of objects). str(exc) is client-safe by construction — it
    names the field, never the model text (raw text is already in Prompt_Log)."""


def _clip(text: str | None) -> str | None:
    """redact() + length cap for one UI-supplied free-text value crossing into the snapshot."""
    cleaned = redact(text)
    cap = get_settings().treatment_free_text_cap
    if cleaned and len(cleaned) > cap:
        return cleaned[:cap]
    return cleaned


def _stale_cutoff(at: datetime | None = None) -> datetime:
    """UpdatedAt values older than this mark a RUNNING claim as abandoned (dead worker or
    lost enqueue) — re-claimable and supersede-able. The clock is bumped per LLM attempt
    (touch_plan), so this measures no-progress, not wall time."""
    return (at or dal.now()) - timedelta(seconds=get_settings().treatment_stale_seconds)


# ---------------------------------------------------------------------------
# Library-controls read (TSG's own tables).
#
# Every multi-table statement is built by a module-level `_*_stmt` function so the __main__
# self-check can .compile() each one WITHOUT a database — plain Select.compile() raises
# InvalidRequestError on a malformed join and CompileError on a bad column, which is exactly
# the bug class that once shipped here as an accidental self-join. New statements MUST
# follow this pattern and be added to the self-check list.
# ---------------------------------------------------------------------------
def _library_map_stmt(scenario_id: str):
    cmap, lib = m.Threat_Scenario_Control_Map, m.Control_Library
    return (
        select(cmap.MapRank, lib.ControlLibraryID, lib.ControlCode, lib.Domain, lib.ControlName)
        .join(lib, lib.ControlLibraryID == cmap.ControlLibraryID)
        .where(cmap.ScenarioID == scenario_id,
            lib.IsActive == True, lib.IsDeleted == False)
        .order_by(cmap.MapRank)
    )


def _standards_stmt(control_library_ids: list[int]):
    smap, std = m.Control_Library_Standard_Map, m.Control_Standard
    return (
        select(smap.ControlLibraryID, std.StandardName)
        .join(std, std.StandardID == smap.StandardID)
        .where(smap.ControlLibraryID.in_(control_library_ids),
            std.IsActive == True, std.IsDeleted == False)
        .order_by(std.StandardName)
    )


def _library_controls(sess: Session, scenario_id: str) -> list[dict[str, Any]]:
    """The scenario's Step-4 grounded Control_Library rows, as plain dicts. Same join shape as
    sessions._query_controls, deliberately re-issued here rather than imported — API→pipeline
    is the only allowed import direction, and pulling the session router in would drag the
    whole API layer into every worker."""
    rows = sess.execute(_library_map_stmt(scenario_id)).mappings().all()
    std_names: dict[int, list[str]] = {}
    if rows:
        for cid, name in sess.execute(
            _standards_stmt(sorted({r["ControlLibraryID"] for r in rows}))
        ):
            std_names.setdefault(cid, []).append(name)
    return [
        {"control_library_id": r["ControlLibraryID"], "control_code": r["ControlCode"],
         "domain": r["Domain"], "control_name": r["ControlName"],
         "standards": std_names.get(r["ControlLibraryID"], [])}
        for r in rows
    ]


# ---------------------------------------------------------------------------
# Snapshot builder (POST time)
# ---------------------------------------------------------------------------
def _loads(blob: str | None, default):
    try:
        parsed = json.loads(blob) if blob else default
    except (TypeError, ValueError):
        return default
    return parsed if isinstance(parsed, type(default)) else default


def regen_risk_input_from_snapshot(snapshot: dict[str, Any]) -> dict[str, Any]:
    """The regenerate route's register half: rebuild the `risk_input` dict from the ACTIVE plan's
    frozen InputSnapshotJSON, so `/regenerate` needs no body at all and build_treatment_input
    stays the ONE snapshot recipe (fresh TSG-derived half every time — honors a restored scenario
    version).

    Reverse-maps exactly the register-sourced keys, named exhaustively because the
    `existing_controls` block MIXES register data with TSG-derived data (library_mapped/
    _count must be rebuilt fresh, never carried): `register_controls`,
    `applied_to_all_subsystems`, `applied_to_all_subsystems_justification`, the whole
    `risk_assessment` block INCLUDING its assessment window, and the echo-only `register` block.
    Carried values are already clipped/redacted; build_treatment_input re-applies both, which is
    idempotent, so the stored bytes survive the round trip."""
    controls = snapshot.get("existing_controls") or {}
    assessment = snapshot.get("risk_assessment") or {}
    register = snapshot.get("register") or {}
    # [Fix] The window used to be dropped here entirely, so every regenerate silently discarded
    # the deadline the original plan was written against. The STORED keys are timeline_* (a frozen
    # record format, unchanged by the mitigation_* request rename — see _assessment_window), and
    # what _assessment_window READS is mitigation_*, so this is a deliberate translation: it
    # rebuilds the window for every row ever written, not just post-rename ones.
    window = assessment.get("assessment_window") or {}
    return {
        "existing_controls": controls.get("register_controls") or [],
        "existing_controls_all_subsystems": controls.get("applied_to_all_subsystems"),
        "existing_controls_all_subsystems_justification":
            controls.get("applied_to_all_subsystems_justification"),
        "likelihood_rating": assessment.get("likelihood_rating"),
        "impact_rating": assessment.get("impact_rating"),
        "final_risk_rating": assessment.get("final_risk_rating"),
        "risk_level": assessment.get("risk_level"),
        "impacted_business_division": assessment.get("impacted_business_division"),
        "mitigation_start_date": window.get("timeline_start_date"),
        "mitigation_end_date": window.get("timeline_end_date"),
        "risk_identification_date": register.get("risk_identification_date"),
        "risk_owner": register.get("risk_owner"),
    }


def build_treatment_input(sess: Session, session_row: dict, scenario_row: dict,
                          risk_input: dict[str, Any]) -> dict[str, Any]:
    """The frozen LLM context (SDD §7.2), persisted verbatim as InputSnapshotJSON.

    `risk_input` is the validated TreatmentPlanBody as a dict — the register's half of the
    context; everything else is extracted from TSG's own tables. Every free-text value
    crosses redact()ed (and length-capped) INSIDE the JSON object — never as prose — so a
    value that reads like an instruction stays data.

    Two sub-blocks never reach the model (prompts.treatment_prompt strips them):
    `warnings` (TSG bookkeeping, merged into ValidationJSON at finish) and `register` (the
    echo fields — risk_owner is a person's name the model must never see; the date is banned
    from generation anyway). `impacted_business_division` additionally rides the
    prompt-visible risk_assessment block as org context."""
    warnings: list[str] = []

    asset_context = _loads(session_row.get("AssetContextJSON"), {})
    subsystems = _loads(session_row.get("SubsystemsJSON"), [])
    # Every context field the session froze is sent (SDD §7.2's sector/sub_sector/
    # cii_asset_description included) — build_base_context applies no field-name gate, only
    # redaction and the no-value scrub, so a field is absent here exactly when it was empty
    # or a placeholder in the snapshot.
    base = prompts.build_base_context(
        session_row.get("AssetName") or "", asset_context, subsystems)

    # Threat block — both hops to Identified_Threat are OUTER joins, so a broken linkage
    # nulls the columns; an explicit null + warning beats a silently empty block.
    # Actors come through the ONE shared reader (the stored blob is a dict, not a list), and
    # deliberately through the RAW one: this plan treats a scenario the model ALREADY wrote from
    # that same raw list (dal.active_threats feeds scenario_prompt stored_actors), so a
    # validated_actors gate would hand the treatment [] for every unverified threat and plan
    # against adversaries the scenario it is treating names out loud.
    threat_fields: dict[str, Any] = {
        "category": redact(scenario_row.get("ThreatCategory")),
        "type": redact(scenario_row.get("LibraryThreatType") or scenario_row.get("ThreatType")),
        "name": redact(scenario_row.get("LibraryThreatName") or scenario_row.get("ThreatName")),
        "actors": [redact(a) for a in grounding.stored_actors(scenario_row.get("ThreatActorsJSON")) if a],
    }
    threat: dict[str, Any] | None = threat_fields
    if not threat_fields["type"] and not threat_fields["name"]:
        threat = None
        warnings.append("threat join returned no rows — plan generated without threat identity")

    scenario_json = _loads(scenario_row.get("ScenarioJSON"), {})
    # scenario_suggested is GONE from the snapshot: the LLM no longer proposes controls
    # (library-first redesign), so library_mapped is the whole TSG-derived control input.
    # Legacy snapshots still carrying the key are inert — nothing reads it back.

    # Degrade-to-empty, same rationale as sessions._controls_by_output: a DB where
    # Control_library.sql hasn't run yet must not 500 the POST. The two warnings are
    # deliberately DISTINCT — a hard lookup failure must never masquerade as an empty map.
    lookup_failed = False
    try:
        library_mapped = _library_controls(sess, scenario_row["ScenarioID"])
    except Exception:
        sess.rollback()  # no uncommitted writes exist at this point in the POST
        log.warning("treatment.library_controls_read_failed", exc_info=True)
        library_mapped, lookup_failed = [], True
        warnings.append("library control lookup failed — plan generated without mapped controls")
    if not library_mapped and not lookup_failed:
        warnings.append("no library-mapped controls for this scenario (Step-4 map is empty)")

    date = risk_input.get("risk_identification_date")
    snap: dict[str, Any] = {
        **base,
        "threat": threat,
        "scenario": {
            "scenario_title": redact(scenario_json.get("scenario_title")),
            "scenario_statement": redact(scenario_json.get("scenario_statement")),
            "risk_statement": redact(scenario_json.get("risk_statement")),
            # The scenario's OWN per-system verdicts. Without these the model must judge
            # applicable_to_all_subsystems against `supporting_systems` — the session's whole
            # raw scope — and so is asked to cover systems this scenario already ruled out.
            # Empty for pre-v1.3 scenarios and for sessions with no supporting systems; the
            # prompt names that fallback explicitly, so no warning is warranted.
            "supporting_system_applicability": [
                {"supporting_system": redact((a or {}).get("supporting_system")),
                 "applicable": (a or {}).get("applicable"),
                 "justification": redact((a or {}).get("justification"))}
                for a in scenario_json.get("supporting_system_applicability") or []
                if isinstance(a, dict)],
        },
        "existing_controls": {
            "library_mapped": library_mapped,
            "library_mapped_count": len(library_mapped),
            # The register's controls, verbatim from the request (the gap-analysis baseline).
            "register_controls": [_clip(c) for c in risk_input.get("existing_controls") or []],
            "applied_to_all_subsystems": risk_input.get("existing_controls_all_subsystems"),
            "applied_to_all_subsystems_justification":
                _clip(risk_input.get("existing_controls_all_subsystems_justification")),
        },
        "risk_assessment": {
            "likelihood_rating": risk_input.get("likelihood_rating"),
            "impact_rating": risk_input.get("impact_rating"),
            "final_risk_rating": risk_input.get("final_risk_rating"),
            "risk_level": risk_input.get("risk_level"),
            "impacted_business_division": redact(risk_input.get("impacted_business_division")),
            # The window the ENTIRE assessment must complete within (request pair, validated
            # both-or-neither). PROMPT-VISIBLE on purpose: the model must schedule inside it;
            # _validate_plan then cross-checks the answer against total_days.
            "assessment_window": _assessment_window(risk_input),
        },
        "treatment_strategy": str(TreatmentStrategy.mitigate),
        # Echo-only block — stripped from the prompt, injected into PlanJSON at finish.
        "register": {
            "risk_identification_date": date.isoformat() if isinstance(date, datetime) else date,
            "risk_owner": redact(risk_input.get("risk_owner")),
            "impacted_business_division": redact(risk_input.get("impacted_business_division")),
        },
        "warnings": warnings,
    }
    return snap


# ---------------------------------------------------------------------------
# Output validation + server-owned keys (worker)
# ---------------------------------------------------------------------------
def _as_date(v: Any):
    """A `date` from a date, a datetime, or an ISO string — None if it is none of those.

    [Fix] The request path hands ISO STRINGS here: api/treatment.py dumps the body with
    mode="json", which serializes pydantic's `date` fields to "YYYY-MM-DD". The old code only
    handled real date objects, so on the ONLY path that actually runs it computed no day count at
    all (see _assessment_window). Normalizing every accepted shape HERE — rather than changing the
    one caller's dump mode — is what stops a future caller reintroducing it by choosing a
    different mode. datetime.fromisoformat (not date.fromisoformat) so a full ISO timestamp
    parses too, and so no module-level `date` import shadows build_treatment_input's own local.
    """
    if isinstance(v, datetime):
        return v.date()
    if hasattr(v, "toordinal"):   # a real date; datetime is already handled above
        return v
    if isinstance(v, str):
        try:
            return datetime.fromisoformat(v).date()
        except ValueError:
            return None
    return None


def _assessment_window(risk_input: dict[str, Any]) -> dict[str, Any] | None:
    """{timeline_start_date, timeline_end_date, total_days} from the request pair, or None.
    total_days is computed server-side so the model reasons over one unambiguous number and
    the post-generation check compares against the same one.

    STORED KEY NAMES STAY timeline_* while the REQUEST fields are mitigation_*, deliberately: the
    snapshot is a persisted record format — read back by regenerate and served verbatim by the
    evidence endpoint — so renaming the request contract must not rewrite the shape of every row
    already in the table. regen_risk_input_from_snapshot translates between the two.
    """
    raw_start = risk_input.get("mitigation_start_date")
    raw_end = risk_input.get("mitigation_end_date")
    if not raw_start or not raw_end:   # both-or-neither is enforced by the request model
        return None
    start, end = _as_date(raw_start), _as_date(raw_end)
    if start is None or end is None:
        # Both values were supplied but at least one will not parse — a corrupted snapshot, or a
        # caller passing a shape _as_date does not know. Say so out loud: returning a silent None
        # is precisely what hid the original bug, and it disables _window_violations for the whole
        # plan rather than for one field.
        log.warning("treatment.assessment_window_unparseable",
                    start=repr(raw_start), end=repr(raw_end))
        return None
    return {"timeline_start_date": start.isoformat(), "timeline_end_date": end.isoformat(),
            "total_days": (end - start).days}


_DURATION_DAYS = re.compile(r"(\d+)\s*(day|week|month)", re.IGNORECASE)
_DURATION_UNIT_DAYS = {"day": 1, "week": 7, "month": 30}


def _window_violations(parsed: dict[str, Any], window: dict[str, Any] | None) -> list[str]:
    """Advisory check that the plan fits the assessment window (Part 3 of the register spec):
    every parsable relative duration — the overall mitigation_timeline and each action's
    timeline — must fit within total_days. Flags, never blocks, same posture as the
    vocabulary clamps: the reviewer sees exactly which line overran and by what."""
    if not window or not window.get("total_days"):
        return []
    budget = int(window["total_days"])

    def worst_days(text: str | None) -> int | None:
        hits = [_DURATION_UNIT_DAYS[u.lower()] * int(n)
                for n, u in _DURATION_DAYS.findall(str(text or ""))]
        return max(hits) if hits else None

    out: list[str] = []
    overall = worst_days(parsed.get("mitigation_timeline"))
    if overall is not None and overall > budget:
        out.append(f"mitigation_timeline ({parsed.get('mitigation_timeline')!r}) exceeds the "
                f"assessment window of {budget} days")
    for i, act in enumerate(parsed.get("remediation_action_plan") or []):
        if not isinstance(act, dict):
            continue
        d = worst_days(act.get("timeline"))
        if d is not None and d > budget:
            out.append(f"remediation_action_plan[{i}].timeline ({act.get('timeline')!r}) "
                    f"exceeds the assessment window of {budget} days")
    return out


def _validate_plan(parsed: dict[str, Any]) -> list[str]:
    """Structural requirement + advisory vocabulary clamps (SDD §6.2 step 4). Both tables MUST
    be present — controls_to_be_implemented.controls (nested under the coverage verdict) and
    remediation_action_plan — a plan without them is unusable, so that raises
    TreatmentPlanInvalid (→ ERROR row, client-safe message). Everything else flags, never
    blocks: out-of-vocab values are kept and reported in the returned warnings. Vocabularies
    come from the enums — the same members the prompt advertises and the API types."""
    warnings: list[str] = []
    cti = parsed.get("controls_to_be_implemented")
    if not isinstance(cti, dict):
        raise TreatmentPlanInvalid(
            "LLM plan is missing required object 'controls_to_be_implemented'")
    controls = cti.get("controls")
    if not isinstance(controls, list) or not all(isinstance(r, dict) for r in controls):
        raise TreatmentPlanInvalid(
            "LLM plan is missing required table 'controls_to_be_implemented.controls'")
    actions = parsed.get("remediation_action_plan")
    if not isinstance(actions, list) or not all(isinstance(r, dict) for r in actions):
        raise TreatmentPlanInvalid("LLM plan is missing required table 'remediation_action_plan'")
    # Every clamp is an EXACT match against the vocabulary the prompt advertises (built from
    # the same enums) — one posture for all four, so any case-variant draws a warning rather
    # than silently violating the wire vocabulary.
    control_types = {str(v) for v in ControlType}
    priorities = {str(v) for v in ActionPriority}
    for i, ctl in enumerate(controls):
        if ctl.get("control_type") not in control_types:
            warnings.append(f"controls_to_be_implemented.controls[{i}].control_type out of "
                            f"vocabulary: {ctl.get('control_type')!r}")
        if ctl.get("priority") not in priorities:
            warnings.append(f"controls_to_be_implemented.controls[{i}].priority out of "
                            f"vocabulary: {ctl.get('priority')!r}")
    for i, act in enumerate(actions):
        if act.get("priority") not in priorities:
            warnings.append(f"remediation_action_plan[{i}].priority out of vocabulary: "
                            f"{act.get('priority')!r}")
    if parsed.get("applicable_to_all_subsystems") not in {str(v) for v in YesNo}:
        warnings.append("applicable_to_all_subsystems is not Yes/No: "
                        f"{parsed.get('applicable_to_all_subsystems')!r}")
    coverage = cti.get("control_coverage")
    if coverage not in {str(v) for v in ControlCoverage}:
        warnings.append(f"controls_to_be_implemented.control_coverage out of vocabulary: "
                        f"{coverage!r}")
    elif coverage == str(ControlCoverage.covered) and controls:
        warnings.append("controls_to_be_implemented.control_coverage says 'covered' but "
                        "controls is non-empty")
    return warnings


def _resolve_control_library_ids(parsed: dict[str, Any], snapshot: dict[str, Any]) -> None:
    """Put `control_library_id` on each recommended control, and DROP any control that
    doesn't resolve to one — every control in the persisted plan must be a real
    Control_Library row, never text the model invented.

    The model is never shown a primary key (prompts._EXCLUDE_DB_KEY_TO_PROMPT): it echoes the
    stable `control_code` instead. The id is resolved HERE, server-side, from the snapshot's own
    library_mapped rows. Both keys are kept on a surviving control: the code is what a human
    reads, the id is what joins.

    The join key travels through model-reproduced free text, so it is FOLDED (strip + casefold)
    on both sides before lookup — the same posture as every other model-echoed identifier in the
    pipeline (accept.py's name folding, _ground_entry_points' casefold entry points, embeddings'
    normalisation). A bare exact match would send ' CII-CID-028' or 'cii-cid-028' to no match,
    indistinguishable from an invented code, and one model version that lowercases its output
    would silently drop every control in every plan. ControlCode is unique among live rows, so
    folding cannot produce a wrong-row match — only a recovered one. The canonical code is
    written back too, so the human-visible half is repaired as well.
    """
    by_code = {str(c["control_code"]).strip().casefold(): c
            for c in ((snapshot.get("existing_controls") or {}).get("library_mapped") or [])
            if isinstance(c, dict) and c.get("control_code") and c.get("control_library_id")}
    cti = parsed.get("controls_to_be_implemented") or {}
    kept: list[dict] = []
    dropped: list[str] = []
    for ctl in cti.get("controls") or []:
        if not isinstance(ctl, dict):
            continue
        raw = str(ctl.get("control_code") or "").strip()
        hit = by_code.get(raw.casefold())
        if hit is None:
            dropped.append(raw or "<no control_code>")
            continue
        ctl["control_library_id"] = hit["control_library_id"]
        ctl["control_code"] = hit["control_code"]   # canonical spelling, not the echo
        kept.append(ctl)
    cti["controls"] = kept
    # A dropped control means the model invented/mistyped a code — either way it isn't a
    # library entry and must not reach the persisted plan. Logged rather than silent: an
    # occasional invented code is expected, but one that SHOULD have matched is a join-key loss.
    if dropped:
        log.info("treatment.control_code_unresolved_dropped", codes=dropped,
                known=sorted(c["control_code"] for c in by_code.values()))


def _inject_reserved(parsed: dict[str, Any], snapshot: dict[str, Any]) -> dict[str, Any]:
    """Stamp/echo the server-owned plan keys (_RESERVED_PLAN_KEYS), OVERWRITING any
    same-named key the model emitted — AI output can never impersonate register data:
    - treatment_plan: the server-side strategy stamp;
    - the three register echoes, from the snapshot's prompt-hidden `register` block.
    controls_to_be_implemented.controls is filtered here too (see
    _resolve_control_library_ids): only entries that resolve to a real library_mapped
    control survive, so a control never reaches the plan without a Control_Library row."""
    register = snapshot.get("register") or {}
    parsed["treatment_plan"] = str(TreatmentStrategy.mitigate)
    parsed["risk_identification_date"] = register.get("risk_identification_date")
    parsed["risk_owner"] = register.get("risk_owner")
    parsed["impacted_business_division"] = register.get("impacted_business_division")
    _resolve_control_library_ids(parsed, snapshot)
    return parsed


def _narrative_text(parsed: dict[str, Any]) -> str:
    """The plan's prose fields, concatenated for one moderation call. Most of the model's free
    text now lives in the two tables rather than in dedicated narrative fields, so their prose
    columns (control description, action) feed in alongside the remaining scalars."""
    parts = [str(parsed.get(k) or "") for k in ("title", "action_plan", "mitigation_timeline")]
    controls = (parsed.get("controls_to_be_implemented") or {}).get("controls") or []
    parts += [str(c.get("description") or "") for c in controls if isinstance(c, dict)]
    parts += [str(a.get("action") or "") for a in parsed.get("remediation_action_plan") or []
            if isinstance(a, dict)]
    return "\n".join(p for p in parts if p)


def _classify_failure(exc: Exception) -> tuple[TreatmentOutcomeReason, str]:
    """One terminal failure -> (reason a client switches on, message a human reads).

    The reason is the contract; the message is never parsed. Both are derived here so the two can
    never disagree, and so the wire carries no `repr(exc)` — `_failure_client_message` returns one
    for a parse error, which is fine for the stage pipeline's logs but is an unstable Python
    detail to publish. Here the reason already says "the model's reply was unusable", so the
    message can be a fixed sentence."""
    if isinstance(exc, TreatmentPlanInvalid):
        # Its own message names the missing table — precise, client-safe, worth keeping.
        return TreatmentOutcomeReason.invalid_plan, str(exc)
    if isinstance(exc, LLMResponseParseError):
        return TreatmentOutcomeReason.invalid_plan, "the model's reply was not usable JSON"
    # Shared classifier: a stable TOKEN, never the English message — a rewording of the
    # client text can no longer silently degrade content_blocked to generation_failed.
    kind, msg = _classify_llm_failure(exc)
    if kind == "guardrail":
        return TreatmentOutcomeReason.content_blocked, msg
    return TreatmentOutcomeReason.generation_failed, msg


def _plan_result_event(row, plan_id: str, status: StageStatus,
                    reason: TreatmentOutcomeReason | None = None) -> dict:
    """The advisory SSE payload for one finished plan. Split from the publish so the self-check
    can assert it against TreatmentPlanResultEvent without a bus or a DB. StrEnum members serialize
    as their value, so no str() conversion is needed here."""
    event = {"type": SSEEventType.treatment_plan_result,
            "session_id": row["SessionID"], "ScenarioID": row["ScenarioID"],
            "plan_id": plan_id, "status": status, "ts": dal.now().isoformat()}
    if reason is not None:
        event["reason"] = reason
    return event


def _publish_plan_result(row, plan_id: str, status: StageStatus,
                        reason: TreatmentOutcomeReason | None = None) -> None:
    """Tell any open SSE stream this plan finished, so the UI refetches now instead of on its next
    poll. Three rules, each with a failure mode that is invisible until it bites:

    AFTER the commit, never before. The bus has no replay log, so the durable row must be visible
    first — publishing earlier makes the client refetch and read the OLD status, and the spinner
    never clears (the ordering rule cascade.py:166-171 states for its own advisory events).

    Channel from row["SessionID"], never a path param. Redis channel names are byte-exact and the
    subscriber keys off the canonical row value (app/api/sessions.py:855-858); a differently-cased
    id opens a channel nobody listens on, so the stream authorizes, reconciles, then delivers
    nothing but heartbeats forever.

    Never raises — bus.publish swallows everything behind its circuit breaker (app/sse/bus.py:82).
    That is load-bearing here: the COMPLETE call site sits inside the worker's try/except, so a
    raising publish would be caught by the terminal handler and try to park an already-finished
    row, logging a contradictory finish_dropped.

    A HINT, not a completion contract. Only a winning finish CAS publishes, so three outcomes are
    silent: a dead worker (row stays RUNNING; only the GET's read-time projection calls it timed
    out, and there is no reaper to fire one later), an LLMSlotUnavailable autoretry (which bumps
    the progress clock every attempt, so the row never even goes stale), and cancel plus a plain
    review verdict (written in the API process). One API-side action DOES publish: an approve that
    switches the active version (review with a historical plan_id) emits this same event shape
    after its commit, so watching clients refetch the swapped-in plan. A publish failure
    additionally silences this whole worker process for a cooldown window. Clients MUST keep a
    slow backstop poll."""
    bus.publish(row["SessionID"], _plan_result_event(row, plan_id, status, reason))


# ---------------------------------------------------------------------------
# Worker body (Celery task delegate)
# ---------------------------------------------------------------------------
def run_treatment_generation(sess: Session, plan_id: str, llm: LLMClient, task_id: str) -> None:
    """One plan attempt: claim CAS → prompt from the frozen snapshot → validate → inject the
    server-owned keys → finish CAS. Safe under acks_late redelivery AND autoretry (both
    re-run with the SAME task id — the claim's own-task branch resumes them; a bare read here
    would run two LLM calls in parallel). LLMSlotUnavailable propagates for Celery's
    autoretry; everything else parks the row in ERROR with a client-safe message."""
    settings = get_settings()
    if not dal.claim_plan(sess, plan_id, task_id, _stale_cutoff()):
        sess.rollback()
        log.info("treatment.claim_rejected", plan_id=plan_id, task_id=task_id)
        return
    sess.commit()  # claim visible before the long call — no open transaction across the LLM

    p = m.Risk_Treatment_Plan
    row = sess.execute(select(p.__table__).where(p.PlanID == plan_id)).mappings().first()
    if row is None:  # defensive only — the claim CAS just matched this PlanID
        log.warning("treatment.row_vanished", plan_id=plan_id)
        return
    # The four columns _ask_ai reads for its Prompt_Log row — all denormalized onto the plan
    # row at insert, so no Scenario_Session re-read is needed here. Scenario_Audit has no
    # UserID column (only ActorUserID, which stays NULL on these worker rows), hence the
    # narrower dict.
    audit_ident = {"SessionID": row["SessionID"], "TenantID": row["TenantID"],
                "EntityID": row["EntityID"], "UserID": row["UserID"]}
    # ScenarioID included: without it these worker-written treatment_plan_outcome rows leave the
    # indexed column NULL, stay OUTSIDE the filtered IX_ScenarioAudit_Scenario, and cannot say WHICH
    # scenario they belong to — so the per-scenario trail had to fetch a whole session and discard
    # the rest in Python. It is not an optimisation: a row that cannot name its subject is unusable
    # in a timeline. The API-side writes were stamped already; these two were the gap.
    audit_cols = {k: audit_ident[k] for k in ("SessionID", "TenantID", "EntityID")}
    audit_cols["ScenarioID"] = row["ScenarioID"]
    audit_cols["PlanID"] = plan_id   # the plan dimension, same reason as ScenarioID
    try:
        snapshot = _loads(row["InputSnapshotJSON"], {})
        messages = prompts.treatment_prompt(snapshot)
        # Progress-clock bump per attempt: staleness must measure "no progress", not wall
        # time — a healthy worker deep in LLMSlotUnavailable backoff never looks dead.
        # DURABILITY NOTE: this UPDATE is committed by _ask_ai's own pre-chat sess.commit();
        # if that commit is ever moved/conditional, commit here or the clock stops being
        # written and long runs become falsely reapable.
        dal.touch_plan(sess, plan_id)
        parsed, _prov = _ask_ai(
            sess, llm, messages, scenario_session=audit_ident,
            subsystem_id=ASSET_UNIT_ID, stage="treatment_plan",
            correlation_id=plan_id,  # stamps the Prompt_Log receipt for the evidence API
            expected_type=dict, temperature=settings.treatment_temperature)
        warnings = (list(snapshot.get("warnings") or []) + _validate_plan(parsed)
                    + _window_violations(parsed,
                                        (snapshot.get("risk_assessment") or {}).get("assessment_window")))
        parsed = _inject_reserved(parsed, snapshot)
        moderation = llm_mod.moderate(_narrative_text(parsed))  # free function, NOT a client method
        validation_json = json.dumps({
            "warnings": warnings,
            "moderation": {"checked": moderation.checked, "flagged": moderation.flagged,
                        "categories": moderation.categories, "error": moderation.error},
        })
        if not dal.finish_plan(sess, plan_id, status=StageStatus.COMPLETE, task_id=task_id,
                            plan_json=json.dumps(parsed), validation_json=validation_json):
            # Superseded mid-flight (a regenerate/version-switch took over) — drop the result; the new row owns
            # the scenario now. Prompt_Log still records the spend (committed in _ask_ai).
            sess.rollback()
            log.info("treatment.finish_dropped", plan_id=plan_id)
            return
        dal.append_audit(sess, AuditID=dal.guid(), **audit_cols,
                        SubsystemID=ASSET_UNIT_ID,
                        EventType=AuditEventType.treatment_plan_outcome,
                        DetailJSON=json.dumps({"plan_id": plan_id,
                                                "status": str(StageStatus.COMPLETE),
                                                "warnings": len(warnings)}))
        sess.commit()
        _publish_plan_result(row, plan_id, StageStatus.COMPLETE)  # after the commit — see docstring
        log.info("treatment.complete", plan_id=plan_id, warnings=len(warnings))
    except LLMSlotUnavailable:
        sess.rollback()
        raise  # Celery autoretry; the claim's own-task branch resumes on the retry
    except Exception as exc:  # noqa: BLE001 — terminal: park the row, never crash the worker
        sess.rollback()  # discards only post-_ask_ai work; the Prompt_Log commit already landed
        reason, client_msg = _classify_failure(exc)
        # Fenced like the success path: if the CAS matched nothing (another delivery already
        # finished the row, or a regenerate superseded it), writing an ERROR audit row would
        # contradict the plan's real state — drop it instead.
        if dal.finish_plan(sess, plan_id, status=StageStatus.ERROR, task_id=task_id,
                        error_message=client_msg, error_reason=reason):
            dal.append_audit(sess, AuditID=dal.guid(), **audit_cols,
                            SubsystemID=ASSET_UNIT_ID,
                            EventType=AuditEventType.treatment_plan_outcome,
                            DetailJSON=json.dumps({"plan_id": plan_id,
                                                    "status": str(StageStatus.ERROR),
                                                    "reason": str(reason),  # switchable in the audit feed too
                                                    "error": client_msg}))
            sess.commit()
            _publish_plan_result(row, plan_id, StageStatus.ERROR, reason)  # after commit — see docstring
        else:
            sess.rollback()
            log.info("treatment.finish_dropped", plan_id=plan_id, error=client_msg)
        log.error("treatment.failed", plan_id=plan_id, error=repr(exc))


if __name__ == "__main__":  # self-check: pure logic only, no DB, no LLM (SDD §13.3)
    # Statement grammar check: plain .compile() catches malformed joins (InvalidRequestError)
    # and bad columns (CompileError) with no database — exactly the class of bug that once
    # shipped here as an accidental self-join. Every new statement builder MUST be added.
    for _stmt in (_library_map_stmt("00000000-0000-0000-0000-000000000000"),
                _standards_stmt([1])):
        _stmt.compile()

    # The advisory SSE payload must satisfy the model the API publishes to /openapi.json — the one
    # drift the manual two-terminal test cannot catch (a wrong key still "arrives", just unusable).
    from app.api.schemas import TreatmentPlanResultEvent
    _ev = _plan_result_event(
        {"SessionID": "5b7c9d21-93a4-4f10-9a83-0f4c113b2a1e",
        "ScenarioID": "1a2b3c4d-5e6f-4788-898a-8b8c8d8e8f90"},
        "b9fe2c07-4d3a-4a51-8e2f-6c1d90a7e4b3", StageStatus.COMPLETE)
    assert TreatmentPlanResultEvent(**_ev).status == "COMPLETE"
    assert _ev["type"] == "treatment_plan_result"
    assert "reason" not in _ev, "COMPLETE carries no reason"
    _err = _plan_result_event(
        {"SessionID": "5b7c9d21-93a4-4f10-9a83-0f4c113b2a1e",
        "ScenarioID": "1a2b3c4d-5e6f-4788-898a-8b8c8d8e8f90"},
        "b9fe2c07-4d3a-4a51-8e2f-6c1d90a7e4b3", StageStatus.ERROR,
        TreatmentOutcomeReason.cancelled)
    assert TreatmentPlanResultEvent(**_err).reason == "cancelled"

    # _classify_failure: every terminal exception maps to a reason, and none leaks a repr().
    assert _classify_failure(TreatmentPlanInvalid("missing table 'x'")) == (
        TreatmentOutcomeReason.invalid_plan, "missing table 'x'")
    _r, _m = _classify_failure(LLMResponseParseError("boom", dict))
    assert _r is TreatmentOutcomeReason.invalid_plan and "LLMResponseParseError" not in _m
    assert _classify_failure(RuntimeError("db down"))[0] is TreatmentOutcomeReason.generation_failed
    # Guardrail path — previously ZERO test signal, and previously matched by English text.
    # __new__ skips the constructor: the classifier only isinstance-checks, never reads attrs.
    from litellm.exceptions import RejectedRequestError as _RRE
    assert _classify_failure(_RRE.__new__(_RRE)) == (
        TreatmentOutcomeReason.content_blocked,
        "content blocked by a configured safety guardrail")

    # validated_actors: the stored dict shape round-trips; corrupt/mis-shaped blobs -> [].
    assert grounding.validated_actors('{"actors": ["APT x"], "validated": true}') == ["APT x"]
    assert grounding.validated_actors('{"actors": ["APT x"], "validated": false}') == []
    assert grounding.validated_actors("not json") == []
    assert grounding.validated_actors(None) == []

    # stored_actors is what build_treatment_input reads — the whole point is the UNVERIFIED
    # case, where the gated reader would blind the plan to the scenario's own adversaries.
    assert grounding.stored_actors('{"actors": ["APT x"], "validated": false}') == ["APT x"]
    assert grounding.stored_actors("not json") == [] and grounding.stored_actors(None) == []

    # _validate_plan: structural violation raises; vocab violations warn but keep the row;
    # covered-with-recommendations inconsistency is flagged (now nested under
    # controls_to_be_implemented.control_coverage rather than a top-level key).
    bad_vocab = {
        "controls_to_be_implemented": {
            "control_coverage": "covered",
            "controls": [{"control_type": "quantum", "control_name": "X", "description": "d",
                        "priority": "Urgent"}]},
        "remediation_action_plan": [
            {"action_id": "A1", "action": "a", "owner": "SOC", "priority": "High"}],
        "applicable_to_all_subsystems": "Maybe",
    }
    warns = _validate_plan(bad_vocab)
    assert any("control_type" in w for w in warns) and any("priority" in w for w in warns)
    assert any("applicable_to_all_subsystems" in w for w in warns)
    assert any("covered" in w for w in warns)  # covered + non-empty controls flagged
    assert _validate_plan({
        "controls_to_be_implemented": {"control_coverage": "covered", "controls": []},
        "remediation_action_plan": [], "applicable_to_all_subsystems": "Yes"}) == []
    try:
        _validate_plan({"controls_to_be_implemented": {"control_coverage": "gaps",
                                                        "controls": "nope"}})
        raise AssertionError("missing table must raise")
    except TreatmentPlanInvalid as e:
        assert "controls_to_be_implemented" in str(e)

    # _narrative_text: 3 named scalars survive (not 8); table prose feeds moderation too, since
    # that is most of what is left to check post-narrowing. mitigation_owner must NOT leak in
    # (it never did — this function had no self-check before, worth closing that gap now).
    narrative = _narrative_text({
        "title": "T", "action_plan": "AP", "mitigation_timeline": "90 days",
        "mitigation_owner": "SOC",
        "controls_to_be_implemented": {"control_coverage": "gaps",
                                    "controls": [{"description": "install MFA"}]},
        "remediation_action_plan": [{"action": "rotate keys"}]})
    assert {"T", "AP", "90 days", "install MFA", "rotate keys"} <= set(narrative.split("\n"))
    assert "SOC" not in narrative

    # _inject_reserved: server keys overwrite AI-emitted impostors; register echoes come from
    # the prompt-hidden block; controls_to_be_implemented.controls is filtered to ONLY entries
    # that resolve to a real library_mapped control_code — "Made-up control" has no match and
    # is dropped, "MFA" resolves and gets its control_library_id stamped on. The drift-pin
    # assert makes adding a key to _RESERVED_PLAN_KEYS without teaching the injector fail here.
    ai_controls = [{"control_name": "MFA", "control_code": "CII-CID-028"},
                {"control_name": "Made-up control", "control_code": "NOT-REAL"}]
    injected = _inject_reserved(
        {"treatment_plan": "Avoid", "risk_owner": "Dr. Evil",
        "controls_to_be_implemented": {"control_coverage": "gaps", "controls": ai_controls}},
        {"register": {"risk_identification_date": "2026-06-14T08:31:00",
                    "risk_owner": "Head of OT Operations",
                    "impacted_business_division": "Water Treatment Operations"},
        "existing_controls": {"library_mapped": [
            {"control_library_id": 28, "control_code": "CII-CID-028"}]}})
    assert injected["treatment_plan"] == "Mitigate"
    kept = injected["controls_to_be_implemented"]["controls"]
    assert [c["control_name"] for c in kept] == ["MFA"]  # unresolved control dropped
    assert kept[0]["control_library_id"] == 28
    assert injected["risk_owner"] == "Head of OT Operations"
    assert injected["impacted_business_division"] == "Water Treatment Operations"
    assert set(_RESERVED_PLAN_KEYS) <= set(injected.keys())  # drift pin
    # Drift pin: _inject_reserved must set EVERY reserved key — add a key to the tuple without
    # teaching the injector about it and this fails, so the overwrite guarantee can't erode.
    assert set(_RESERVED_PLAN_KEYS) <= set(injected.keys())

    # treatment_prompt: house shape — 2 messages, closing format directive, framed context;
    # the prompt-hidden blocks must NOT reach the model.
    msgs = prompts.treatment_prompt({
        "treatment_strategy": "Mitigate", "warnings": ["internal note"],
        "register": {"risk_owner": "Jane Person"}})
    assert len(msgs) == 2 and msgs[0]["role"] == "system" and msgs[1]["role"] == "user"
    assert "Output ONLY the JSON object" in msgs[0]["content"]
    assert msgs[1]["content"].startswith(prompts._CONTEXT_PREFIX)
    assert "internal note" not in msgs[1]["content"]
    assert "Jane Person" not in msgs[1]["content"]

    # Redaction proof: a seeded credential in UI-sent free text must not survive into the
    # snapshot path (_clip is the door body text enters through).
    leaked = _clip("apply patches. db_password=Hunter2SecretValue then reboot")
    assert leaked is not None and "Hunter2SecretValue" not in leaked
    _cap = get_settings().treatment_free_text_cap
    assert len(_clip("x" * (_cap + 500)) or "") == _cap

    # TreatmentConflict carries its wire reason.
    tc = TreatmentConflict("busy", reason=TreatmentGateReason.generation_in_progress)
    assert tc.reason == "generation_in_progress"
    print("treatment self-check ok")
