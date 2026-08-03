"""Risk Treatment (Mitigate) Plan generation — docs/RISK_TREATMENT_PLAN_SDD.md.

Self-contained module in the control_mapping.py mould: the CRM reader, snapshot builder,
output validation and the worker body all live here; the API layer (app/api/treatment.py)
calls the read/build halves at POST time, the Celery task calls run_treatment_generation.

Deliberately OUTSIDE the stage machinery: accepted scenarios exist only on COMPLETED
sessions, where dal.acquire_lock/claim_stage refuse to run — the Risk_Treatment_Plan row's
own Status column is the state, fenced by the conditional-UPDATE helpers in dal.py
(claim_plan / finish_plan / supersede_active_plan). The CRM tables are read ONLY at POST
time (build_treatment_input): the frozen InputSnapshotJSON is what the worker prompts with
and what the GET serves, so a risk row that mutates later never skews a stored plan.
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.enums import AuditEventType, StageStatus, TreatmentGateReason
from app.core.logging import get_logger
from app.core.security import redact
from app.db import dal
from app.db import models as m
from app.pipeline import grounding
from app.pipeline import llm as llm_mod
from app.pipeline import prompts
from app.pipeline.llm import LLMClient, LLMSlotUnavailable
from app.pipeline.tasks import ASSET_UNIT_ID, _ask_ai, _failure_client_message

log = get_logger(__name__)

# Closed vocabularies _validate_plan clamps against (SDD §7.3). Out-of-vocab values are KEPT
# and warned — flag-never-block, same philosophy as ValidationStatus.
_CONTROL_TYPES = {"preventive", "detective", "corrective", "compensating"}
_PRIORITIES = {"Critical", "High", "Medium", "Low"}
_YES_NO = {"Yes", "No"}

# Per-field cap applied to CRM free text at snapshot time (house analog: intel items truncate
# before entering the prompt). CRM columns are nvarchar(max) — an unbounded description would
# blow the prompt budget for zero planning value.
_FREE_TEXT_CAP = 2000


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


def _not_deleted(col):
    """CRM soft-delete filter — every flag column in the v0.1 DDD is NULLable, and NULL means
    'not deleted'; a bare `col == False` would silently drop those rows."""
    return or_(col.is_(None), col == False)  # noqa: E712


def _clip(text: str | None) -> str | None:
    """redact() + length cap for one CRM free-text value crossing into the snapshot."""
    cleaned = redact(text)
    if cleaned and len(cleaned) > _FREE_TEXT_CAP:
        return cleaned[:_FREE_TEXT_CAP]
    return cleaned


def _stale_cutoff(at: datetime | None = None) -> datetime:
    """UpdatedAt values older than this mark a RUNNING claim as abandoned (dead worker or
    lost enqueue) — re-claimable and supersede-able. The clock is bumped per LLM attempt
    (touch_plan), so this measures no-progress, not wall time."""
    return (at or dal.now()) - timedelta(seconds=get_settings().treatment_stale_seconds)


# ---------------------------------------------------------------------------
# CRM read layer (POST time only).
#
# Every multi-table statement is built by a module-level `_*_stmt` function so the __main__
# self-check can .compile() each one WITHOUT a database — plain Select.compile() raises
# InvalidRequestError on a malformed join and CompileError on a bad column, which is exactly
# the bug class that once shipped here as an accidental self-join. New CRM statements MUST
# follow this pattern and be added to the self-check list.
# ---------------------------------------------------------------------------
def _stored_strategy_stmt(crm_id: int):
    """Latest non-deleted treatment-plan row's strategy Name for one risk. join_from pins
    `tp` as the FROM root (only `ts` columns are selected, so SQLAlchemy cannot infer the
    left side on its own — omitting this was the self-join bug)."""
    tp, ts = m.crm_risk_identification_treatment_plan, m.crm_risk_identification_treatment_strategy
    return (
        select(ts.Name)
        .join_from(tp, ts, ts.Id == tp.crm_risk_identification_treatment_strategy_id)
        .where(tp.crm_risk_identification_id == crm_id,
               _not_deleted(tp.IsDeleted), _not_deleted(ts.IsDeleted))
        .order_by(tp.creation_date.desc(), tp.Id.desc())
        .limit(1)
    )


def _band_stmt(rating_plan_id: int, score: float):
    r, c = m.crm_risk_rating, m.crm_risk_rating_category
    return (
        select(r.risk_level, r.Priority, r.remediation_time, r.response_time)
        .join(c, c.Id == r.crm_risk_rating_category_id)
        .where(c.crm_risk_rating_plan_id == rating_plan_id,
               _not_deleted(r.IsDeleted), _not_deleted(c.is_deleted),
               r.risk_score_from <= score, r.risk_score_to >= score)
        .order_by(r.risk_score_from)
    )


def _crm_controls_stmt(crm_id: int):
    cd, cs = m.crm_risk_control_details, m.crm_risk_control_status
    return (
        select(cd.action_plan, cs.name, cd.control_effectiveness_score)
        .outerjoin(cs, cs.id == cd.crm_risk_control_status_id)
        .where(cd.crm_risk_identification_id == crm_id,
               or_(cd.is_active.is_(None), cd.is_active == True))  # noqa: E712
    )


def _library_map_stmt(output_id: str):
    cmap, lib = m.Threat_Scenario_Control_Map, m.Control_Library
    return (
        select(cmap.MapRank, lib.ControlLibraryID, lib.ControlCode, lib.Domain, lib.ControlName)
        .join(lib, lib.ControlLibraryID == cmap.ControlLibraryID)
        .where(cmap.OutputID == output_id,
               lib.IsActive == True, lib.IsDeleted == False)  # noqa: E712
        .order_by(cmap.MapRank)
    )


def _standards_stmt(control_library_ids: list[int]):
    smap, std = m.Control_Library_Standard_Map, m.Control_Standard
    return (
        select(smap.ControlLibraryID, std.StandardName)
        .join(std, std.StandardID == smap.StandardID)
        .where(smap.ControlLibraryID.in_(control_library_ids),
               std.IsActive == True, std.IsDeleted == False)  # noqa: E712
        .order_by(std.StandardName)
    )


def _band(sess: Session, rating_plan_id: int | None, score: float | None) -> dict[str, Any] | None:
    """*THE* per-risk rating source (SDD D7): the crm_risk_rating band whose
    [risk_score_from, risk_score_to] range (inclusive both ends) contains `score`, scoped to
    the assessment's rating plan via crm_risk_rating_category. Returns
    {label, priority, remediation_time, response_time} or None (no plan, no score, or no
    matching band — the prompt RULES forbid the model inventing a label to fill the gap).
    Overlapping ranges resolve to the lowest risk_score_from, deterministically.

    ASSUMPTION (SDD §14, open with the CRM team): one rating category per rating plan. The
    filter scopes to the PLAN only — if a live plan holds multiple categories (one band set
    per risk category), this can pick a neighbouring category's band. The risk row exposes no
    category id today; when it does, mirror it and add it to the WHERE."""
    if rating_plan_id is None or score is None:
        return None
    row = sess.execute(_band_stmt(rating_plan_id, score)).first()
    if row is None:
        return None
    return {"label": row[0], "priority": row[1],
            "remediation_time": row[2], "response_time": row[3]}


def _option_label(sess: Session, option_id: int | None) -> str | None:
    if option_id is None:
        return None
    return sess.execute(
        select(m.crm_risk_identification_option_value.label)
        .where(m.crm_risk_identification_option_value.id == option_id)
    ).scalar()


def load_crm_risk_context(sess: Session, crm_id: int) -> dict[str, Any] | None:
    """Everything the treatment plan consumes from the CRM Risk module, in one dict — or None
    when the risk row is absent or soft-deleted (the API 404s; absent and foreign must be
    indistinguishable to the caller of the endpoint). Table EXISTENCE is not probed here:
    invariants._assert_crm_tables made that a boot concern (SDD D3).

    `group_id` may come back None (all DDD columns are nullable, or the assessment row is
    missing) — the API's affirmative ownership check then denies, per the house
    no-proven-owner-means-deny rule (dal.py asset_owning_entities)."""
    ri = m.crm_risk_identification
    risk = sess.execute(select(ri.__table__).where(ri.id == crm_id)).mappings().first()
    if risk is None or risk["is_deleted"]:
        return None

    assessment = None
    if risk["crm_assessment_id"] is not None:
        a = m.crm_assessment
        assessment = sess.execute(
            select(a.group_id, a.crm_risk_rating_plan_id)
            .where(a.id == risk["crm_assessment_id"], _not_deleted(a.is_deleted))
        ).first()
    group_id = assessment[0] if assessment else None
    rating_plan_id = assessment[1] if assessment else None

    entity_name = None
    if group_id is not None:
        entity_name = sess.execute(
            select(m.group_table.name).where(m.group_table.id == group_id)).scalar()

    # Latest non-deleted treatment-plan row -> the strategy the toolkit actually recorded.
    stored_strategy = sess.execute(_stored_strategy_stmt(crm_id)).scalar()

    # Existing controls, with their status label — a Planned control must not read as
    # protection the asset already has (prompt RULE 3 depends on this distinction).
    controls = [
        {"action_plan": r[0], "status": r[1], "effectiveness": r[2]}
        for r in sess.execute(_crm_controls_stmt(crm_id)).all()
    ]

    return {
        "risk_id": crm_id,
        "group_id": group_id,
        "entity_name": entity_name,
        "rating_plan_id": rating_plan_id,
        "stored_strategy": stored_strategy,
        "description": risk["description"],
        "root_cause": risk["root_cause"],
        "risk_owner": risk["risk_owner"],
        "likelihood": _option_label(sess, risk["crm_risk_likelihood_id"]),
        "impact": _option_label(sess, risk["crm_risk_impact_id"]),
        "inherent_risk_score": risk["inherent_risk_score"],
        "control_effectiveness_score": risk["control_effectiveness_score"],
        "residual_risk_score": risk["residual_risk_score"],
        "creation_date": risk["creation_date"],  # -> RiskIdentificationDate, never AI-generated
        "controls": controls,
        "inherent_band": _band(sess, rating_plan_id, risk["inherent_risk_score"]),
        "residual_band": _band(sess, rating_plan_id, risk["residual_risk_score"]),
    }


def _library_controls(sess: Session, output_id: str) -> list[dict[str, Any]]:
    """The scenario's Step-4 grounded Control_Library rows, as plain dicts. Same join shape as
    sessions._query_controls, deliberately re-issued here rather than imported — API→pipeline
    is the only allowed import direction, and pulling the session router in would drag the
    whole API layer into every worker."""
    rows = sess.execute(_library_map_stmt(output_id)).mappings().all()
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


def build_treatment_input(sess: Session, session_row: dict, scenario_row: dict,
                          crm: dict[str, Any],
                          context_fields: dict[str, list[str]]) -> dict[str, Any]:
    """The frozen LLM context (SDD §7.2), persisted verbatim as InputSnapshotJSON. Every
    free-text value crosses redact()ed (and CRM text length-capped) INSIDE the JSON object —
    never as prose — so a value that reads like an instruction stays data. `warnings` rides
    the snapshot and is merged into ValidationJSON at finish time."""
    warnings: list[str] = []

    asset_context = _loads(session_row.get("AssetContextJSON"), {})
    subsystems = _loads(session_row.get("SubsystemsJSON"), [])
    base = prompts.build_base_context(
        session_row.get("AssetName") or "", asset_context, subsystems,
        context_fields.get("asset"), context_fields.get("subsystem"),
        # The spec's prompt template requires these three unconditionally; the curator
        # allowlist fails closed and would otherwise silently drop them (SDD §7.2).
        force_fields={"sector", "sub_sector", "cii_asset_description"})

    # Threat block — both hops to Identified_Threat are OUTER joins, so a broken linkage
    # nulls the columns; an explicit null + warning beats a silently empty block.
    # Actors come through the ONE shared reader (the stored blob is a dict, not a list, and
    # only `validated` actors may reach a register-bound document).
    threat: dict[str, Any] | None = {
        "category": redact(scenario_row.get("ThreatCategory")),
        "type": redact(scenario_row.get("LibraryThreatType") or scenario_row.get("ThreatType")),
        "name": redact(scenario_row.get("LibraryThreatName") or scenario_row.get("ThreatName")),
        "actors": [redact(a) for a in grounding.validated_actors(scenario_row.get("ThreatActorsJSON")) if a],
    }
    if not threat["type"] and not threat["name"]:
        threat = None
        warnings.append("threat join returned no rows — plan generated without threat identity")

    scenario_json = _loads(scenario_row.get("ScenarioJSON"), {})
    suggested = [{"name": redact((c or {}).get("name")), "why": redact((c or {}).get("why"))}
                 for c in scenario_json.get("controls") or [] if isinstance(c, dict)]

    # Degrade-to-empty, same rationale as sessions._controls_by_output: a DB where
    # Control_library.sql hasn't run yet must not 500 the POST. The two warnings are
    # deliberately DISTINCT — a hard lookup failure must never masquerade as an empty map.
    lookup_failed = False
    try:
        library_mapped = _library_controls(sess, scenario_row["OutputID"])
    except Exception:  # noqa: BLE001 — controls are enrichment here; degrade loudly
        sess.rollback()  # no uncommitted writes exist at this point in the POST
        log.warning("treatment.library_controls_read_failed", exc_info=True)
        library_mapped, lookup_failed = [], True
        warnings.append("library control lookup failed — plan generated without mapped controls")
    if not library_mapped and not lookup_failed:
        warnings.append("no library-mapped controls for this scenario (Step-4 map is empty)")

    residual_band = crm.get("residual_band") or {}
    inherent_band = crm.get("inherent_band") or {}
    if crm.get("residual_risk_score") is not None and not residual_band:
        warnings.append("residual score matched no crm_risk_rating band — final_risk_rating null")

    return {
        **base,
        "entity": redact(crm.get("entity_name")),
        "threat": threat,
        "scenario": {
            "scenario_title": redact(scenario_json.get("scenario_title")),
            "scenario_statement": redact(scenario_json.get("scenario_statement")),
            "risk_statement": redact(scenario_json.get("risk_statement")),
        },
        "existing_controls": {
            "scenario_suggested": suggested,
            "library_mapped": library_mapped,
            "library_mapped_count": len(library_mapped),
            "crm_registered": [
                {"action_plan": _clip(c.get("action_plan")), "status": c.get("status"),
                 "effectiveness": c.get("effectiveness")}
                for c in crm.get("controls") or []
            ],
        },
        "risk_assessment": {
            "risk_description": _clip(crm.get("description")),
            "root_cause": _clip(crm.get("root_cause")),
            "risk_owner": redact(crm.get("risk_owner")),
            "likelihood": crm.get("likelihood"),
            "impact": crm.get("impact"),
            "inherent_risk_score": crm.get("inherent_risk_score"),
            "inherent_risk_rating": inherent_band.get("label"),
            "control_effectiveness_score": crm.get("control_effectiveness_score"),
            "residual_risk_score": crm.get("residual_risk_score"),
            "final_risk_rating": residual_band.get("label"),
            "sla": {"remediation_time": residual_band.get("remediation_time"),
                    "response_time": residual_band.get("response_time")},
        },
        "treatment_strategy": "Mitigate",
        "crm_strategy": crm.get("stored_strategy"),
        "warnings": warnings,
    }


# ---------------------------------------------------------------------------
# Output validation (worker)
# ---------------------------------------------------------------------------
def _validate_plan(parsed: dict[str, Any]) -> list[str]:
    """Structural requirement + advisory vocabulary clamps (SDD §6.2 step 4). The two tables
    MUST be lists of dicts — a plan without them is unusable, so that raises
    TreatmentPlanInvalid (→ ERROR row, client-safe message). Everything else flags, never
    blocks: out-of-vocab values are kept and reported in the returned warnings."""
    warnings: list[str] = []
    for key in ("recommended_controls", "remediation_action_plan"):
        table = parsed.get(key)
        if not isinstance(table, list) or not all(isinstance(r, dict) for r in table):
            raise TreatmentPlanInvalid(f"LLM plan is missing required table '{key}'")
    for i, ctl in enumerate(parsed["recommended_controls"]):
        if str(ctl.get("control_type", "")).lower() not in _CONTROL_TYPES:
            warnings.append(f"recommended_controls[{i}].control_type out of vocabulary: "
                            f"{ctl.get('control_type')!r}")
        if ctl.get("priority") not in _PRIORITIES:
            warnings.append(f"recommended_controls[{i}].priority out of vocabulary: "
                            f"{ctl.get('priority')!r}")
    for i, act in enumerate(parsed["remediation_action_plan"]):
        if act.get("priority") not in _PRIORITIES:
            warnings.append(f"remediation_action_plan[{i}].priority out of vocabulary: "
                            f"{act.get('priority')!r}")
    if parsed.get("applicable_to_all_subsystems") not in _YES_NO:
        warnings.append("applicable_to_all_subsystems is not Yes/No: "
                        f"{parsed.get('applicable_to_all_subsystems')!r}")
    return warnings


def _narrative_text(parsed: dict[str, Any]) -> str:
    """The plan's prose fields, concatenated for one moderation call."""
    parts = [str(parsed.get(k) or "") for k in
             ("title", "treatment_objective", "risk_treatment_recommendation", "justification",
              "residual_risk_assessment", "expected_risk_reduction", "mitigation_timeline")]
    parts += [str(v) for v in parsed.get("expected_security_improvements") or []]
    parts += [str(v) for v in parsed.get("risk_mitigation_activities") or []]
    return "\n".join(p for p in parts if p)


# ---------------------------------------------------------------------------
# Worker body (Celery task delegate)
# ---------------------------------------------------------------------------
def run_treatment_generation(sess: Session, plan_id: str, llm: LLMClient, task_id: str) -> None:
    """One plan attempt: claim CAS → prompt from the frozen snapshot → validate → finish CAS.
    Safe under acks_late redelivery AND autoretry (both re-run with the SAME task id — the
    claim's own-task branch resumes them; a bare read here would run two LLM calls in
    parallel). LLMSlotUnavailable propagates for Celery's autoretry; everything else parks
    the row in ERROR with a client-safe message."""
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
    # UserID column (only ActorUserID, back-filled by audit_row), hence the narrower dict.
    audit_ident = {"SessionID": row["SessionID"], "TenantID": row["TenantID"],
                   "EntityID": row["EntityID"], "UserID": row["UserID"]}
    audit_cols = {k: audit_ident[k] for k in ("SessionID", "TenantID", "EntityID")}
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
            expected_type=dict, temperature=settings.treatment_temperature)
        warnings = list(snapshot.get("warnings") or []) + _validate_plan(parsed)
        moderation = llm_mod.moderate(_narrative_text(parsed))  # free function, NOT a client method
        validation_json = json.dumps({
            "warnings": warnings,
            "moderation": {"checked": moderation.checked, "flagged": moderation.flagged,
                           "categories": moderation.categories, "error": moderation.error},
        })
        if not dal.finish_plan(sess, plan_id, status=StageStatus.COMPLETE,
                               plan_json=json.dumps(parsed), validation_json=validation_json):
            # Superseded mid-flight (a re-POST took over) — drop the result; the new row owns
            # the scenario now. Prompt_Log still records the spend.
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
        log.info("treatment.complete", plan_id=plan_id, warnings=len(warnings))
    except LLMSlotUnavailable:
        sess.rollback()
        raise  # Celery autoretry; the claim's own-task branch resumes on the retry
    except Exception as exc:  # noqa: BLE001 — terminal: park the row, never crash the worker
        sess.rollback()  # discards only post-_ask_ai work; the Prompt_Log commit already landed
        client_msg = (str(exc) if isinstance(exc, TreatmentPlanInvalid)
                      else _failure_client_message(exc))
        # Fenced like the success path: if the CAS matched nothing (another delivery already
        # finished the row, or a re-POST superseded it), writing an ERROR audit row would
        # contradict the plan's real state — drop it instead.
        if dal.finish_plan(sess, plan_id, status=StageStatus.ERROR, error_message=client_msg):
            dal.append_audit(sess, AuditID=dal.guid(), **audit_cols,
                             SubsystemID=ASSET_UNIT_ID,
                             EventType=AuditEventType.treatment_plan_outcome,
                             DetailJSON=json.dumps({"plan_id": plan_id,
                                                    "status": str(StageStatus.ERROR),
                                                    "error": client_msg}))
            sess.commit()
        else:
            sess.rollback()
            log.info("treatment.finish_dropped", plan_id=plan_id, error=client_msg)
        log.error("treatment.failed", plan_id=plan_id, error=repr(exc))


if __name__ == "__main__":  # self-check: pure logic only, no DB, no LLM (SDD §13.3)
    # Statement grammar check: plain .compile() catches malformed joins (InvalidRequestError)
    # and bad columns (CompileError) with no database — exactly the class of bug that once
    # shipped here as an accidental self-join in the stored-strategy query. Every new CRM
    # statement builder MUST be added to this list.
    for _stmt in (_stored_strategy_stmt(1), _band_stmt(1, 5.0), _crm_controls_stmt(1),
                  _library_map_stmt("00000000-0000-0000-0000-000000000000"),
                  _standards_stmt([1])):
        _stmt.compile()

    # validated_actors: the stored dict shape round-trips; corrupt/mis-shaped blobs -> [].
    assert grounding.validated_actors('{"actors": ["APT x"], "validated": true}') == ["APT x"]
    assert grounding.validated_actors('{"actors": ["APT x"], "validated": false}') == []
    assert grounding.validated_actors("not json") == []
    assert grounding.validated_actors('["bare", "list"]') == []
    assert grounding.validated_actors(None) == []

    # _validate_plan: structural violation raises; vocab violations warn but keep the row.
    ok_plan = {
        "recommended_controls": [
            {"control_type": "preventive", "control_name": "MFA", "description": "d",
             "priority": "Critical", "control_library_id": None},
            {"control_type": "quantum", "control_name": "X", "description": "d",
             "priority": "Urgent"},
        ],
        "remediation_action_plan": [
            {"action_id": "A1", "action": "a", "owner": "SOC", "priority": "High",
             "dependencies": "None", "timeline": "within 30 days", "success_criteria": "s"},
        ],
        "applicable_to_all_subsystems": "Maybe",
    }
    warns = _validate_plan(ok_plan)
    assert any("control_type" in w for w in warns) and any("priority" in w for w in warns)
    assert any("applicable_to_all_subsystems" in w for w in warns)
    assert _validate_plan({"recommended_controls": [], "remediation_action_plan": [],
                           "applicable_to_all_subsystems": "Yes"}) == []
    try:
        _validate_plan({"recommended_controls": "nope"})
        raise AssertionError("missing table must raise")
    except TreatmentPlanInvalid as e:
        assert "remediation_action_plan" in str(e) or "recommended_controls" in str(e)

    # treatment_prompt: house shape — 2 messages, closing format directive, framed context.
    msgs = prompts.treatment_prompt({"treatment_strategy": "Mitigate"})
    assert len(msgs) == 2 and msgs[0]["role"] == "system" and msgs[1]["role"] == "user"
    assert "Output ONLY the JSON object" in msgs[0]["content"]
    assert msgs[1]["content"].startswith(prompts._CONTEXT_PREFIX)

    # Redaction proof: a seeded credential in CRM free text must not survive into the
    # snapshot path (_clip is the only door CRM text enters through).
    leaked = _clip("apply patches. db_password=Hunter2SecretValue then reboot")
    assert leaked is not None and "Hunter2SecretValue" not in leaked
    assert len(_clip("x" * (_FREE_TEXT_CAP + 500)) or "") == _FREE_TEXT_CAP

    # TreatmentConflict carries its wire reason.
    tc = TreatmentConflict("busy", reason=TreatmentGateReason.generation_in_progress)
    assert tc.reason == "generation_in_progress"
    print("treatment self-check ok")
