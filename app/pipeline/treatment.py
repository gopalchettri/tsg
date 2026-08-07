"""Risk Treatment (Mitigate) Plan generation — docs/RISK_TREATMENT_PLAN_SDD.md.

Self-contained module in the control_mapping.py mould: the snapshot builder, output
validation and the worker body all live here; the API layer (app/api/treatment.py) calls the
build half at POST time, the Celery task calls run_treatment_generation.

TSG reads NO risk-module tables: the register's risk data (ratings, level, existing
controls, echo fields) arrives IN the request body and is frozen — together with TSG's own
scenario/asset/threat/mapped-controls context — into InputSnapshotJSON at POST time. The
worker prompts from that snapshot and the GET serves it, so nothing external can skew a
stored plan.

Deliberately OUTSIDE the stage machinery: accepted scenarios exist only on COMPLETED
sessions, where dal.acquire_lock/claim_stage refuse to run — the Risk_Treatment_Plan row's
own Status column is the state, fenced by the conditional-UPDATE helpers in dal.py
(claim_plan / finish_plan / supersede_active_plan).
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.enums import (ActionPriority, AuditEventType, ControlCoverage, ControlType,
                            StageStatus, TreatmentGateReason, TreatmentStrategy, YesNo)
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

# Plan keys the SERVER owns (docs/RISK_TREATMENT_PLAN_SDD.md — reserved-key rule): stamped or
# echoed at finish time, OVERWRITING anything the model emitted under the same name, so AI
# output can never impersonate register data. (controls_to_be_implemented is NOT here — it is
# the AI's own gap-analysis table, so the injector must never touch it.)
_RESERVED_PLAN_KEYS = ("treatment_plan", "risk_identification_date",
                    "risk_owner", "impacted_business_division")

# Per-field cap applied to UI-supplied free text at snapshot time (house analog: intel items
# truncate before entering the prompt). Pydantic max_length bounds reject oversized fields at
# the boundary; this is defense-in-depth for anything that slips a path around them.
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


def _clip(text: str | None) -> str | None:
    """redact() + length cap for one UI-supplied free-text value crossing into the snapshot."""
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
# Library-controls read (TSG's own tables).
#
# Every multi-table statement is built by a module-level `_*_stmt` function so the __main__
# self-check can .compile() each one WITHOUT a database — plain Select.compile() raises
# InvalidRequestError on a malformed join and CompileError on a bad column, which is exactly
# the bug class that once shipped here as an accidental self-join. New statements MUST
# follow this pattern and be added to the self-check list.
# ---------------------------------------------------------------------------
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

    date = risk_input.get("risk_identification_date")
    snap: dict[str, Any] = {
        **base,
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
    # Regenerate-with-steering: the reviewer's note rides the PROMPT-VISIBLE snapshot (that is
    # the whole point — the model must read it), redacted + capped like all body free text.
    note = _clip(risk_input.get("user_note"))
    if note:
        snap["reviewer_note"] = note
    return snap


# ---------------------------------------------------------------------------
# Output validation + server-owned keys (worker)
# ---------------------------------------------------------------------------
def _validate_plan(parsed: dict[str, Any]) -> list[str]:
    """Structural requirement + advisory vocabulary clamps (SDD §6.2 step 4). The two tables
    MUST be lists of dicts — a plan without them is unusable, so that raises
    TreatmentPlanInvalid (→ ERROR row, client-safe message). Everything else flags, never
    blocks: out-of-vocab values are kept and reported in the returned warnings. Vocabularies
    come from the enums — the same members the prompt advertises and the API types."""
    warnings: list[str] = []
    for key in ("controls_to_be_implemented", "remediation_action_plan"):
        table = parsed.get(key)
        if not isinstance(table, list) or not all(isinstance(r, dict) for r in table):
            raise TreatmentPlanInvalid(f"LLM plan is missing required table '{key}'")
    # Every clamp is an EXACT match against the vocabulary the prompt advertises (built from
    # the same enums) — one posture for all five, so any case-variant draws a warning rather
    # than silently violating the wire vocabulary.
    control_types = {str(v) for v in ControlType}
    priorities = {str(v) for v in ActionPriority}
    for i, ctl in enumerate(parsed["controls_to_be_implemented"]):
        if ctl.get("control_type") not in control_types:
            warnings.append(f"controls_to_be_implemented[{i}].control_type out of vocabulary: "
                            f"{ctl.get('control_type')!r}")
        if ctl.get("priority") not in priorities:
            warnings.append(f"controls_to_be_implemented[{i}].priority out of vocabulary: "
                            f"{ctl.get('priority')!r}")
    for i, act in enumerate(parsed["remediation_action_plan"]):
        if act.get("priority") not in priorities:
            warnings.append(f"remediation_action_plan[{i}].priority out of vocabulary: "
                            f"{act.get('priority')!r}")
    if parsed.get("applicable_to_all_subsystems") not in {str(v) for v in YesNo}:
        warnings.append("applicable_to_all_subsystems is not Yes/No: "
                        f"{parsed.get('applicable_to_all_subsystems')!r}")
    if parsed.get("control_coverage") not in {str(v) for v in ControlCoverage}:
        warnings.append(f"control_coverage out of vocabulary: {parsed.get('control_coverage')!r}")
    elif (parsed["control_coverage"] == str(ControlCoverage.covered)
          and parsed["controls_to_be_implemented"]):
        warnings.append("control_coverage says 'covered' but controls_to_be_implemented is non-empty")
    return warnings


def _resolve_control_library_ids(parsed: dict[str, Any], snapshot: dict[str, Any]) -> None:
    """Put `control_library_id` back on each recommended control, in place.

    The model is never shown a primary key (prompts._EXCLUDE_DB_KEY_TO_PROMPT):
    it echoes the stable `control_code` instead. The id is resolved HERE, server-side, from the
    snapshot's own library_mapped rows — so the persisted plan and the API response still carry
    it, and a code the model invented or mistyped resolves to None rather than to some other
    library row. Both keys are kept: the code is what a human reads, the id is what joins."""
    by_code = {c["control_code"]: c["control_library_id"]
               for c in ((snapshot.get("existing_controls") or {}).get("library_mapped") or [])
               if isinstance(c, dict) and c.get("control_code") and c.get("control_library_id")}
    for ctl in parsed.get("controls_to_be_implemented") or []:
        if isinstance(ctl, dict):
            ctl["control_library_id"] = by_code.get(ctl.get("control_code"))


def _inject_reserved(parsed: dict[str, Any], snapshot: dict[str, Any]) -> dict[str, Any]:
    """Stamp/echo the server-owned plan keys (_RESERVED_PLAN_KEYS), OVERWRITING any
    same-named key the model emitted — AI output can never impersonate register data:
    - treatment_plan: the server-side strategy stamp;
    - the three register echoes, from the snapshot's prompt-hidden `register` block.
    The controls_to_be_implemented table is otherwise the AI's own gap-analysis output; only
    its control_library_id is server-owned, resolved from the model's echoed control_code."""
    register = snapshot.get("register") or {}
    parsed["treatment_plan"] = str(TreatmentStrategy.mitigate)
    parsed["risk_identification_date"] = register.get("risk_identification_date")
    parsed["risk_owner"] = register.get("risk_owner")
    parsed["impacted_business_division"] = register.get("impacted_business_division")
    _resolve_control_library_ids(parsed, snapshot)
    return parsed


def _narrative_text(parsed: dict[str, Any]) -> str:
    """The plan's prose fields, concatenated for one moderation call."""
    parts = [str(parsed.get(k) or "") for k in
             ("title", "treatment_objective", "risk_treatment_recommendation", "justification",
              "action_plan", "residual_risk_assessment", "expected_risk_reduction",
              "mitigation_timeline")]
    parts += [str(v) for v in parsed.get("expected_security_improvements") or []]
    parts += [str(v) for v in parsed.get("risk_mitigation_activities") or []]
    return "\n".join(p for p in parts if p)


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
            correlation_id=plan_id,  # stamps the Prompt_Log receipt for the evidence API
            expected_type=dict, temperature=settings.treatment_temperature)
        warnings = list(snapshot.get("warnings") or []) + _validate_plan(parsed)
        parsed = _inject_reserved(parsed, snapshot)
        moderation = llm_mod.moderate(_narrative_text(parsed))  # free function, NOT a client method
        validation_json = json.dumps({
            "warnings": warnings,
            "moderation": {"checked": moderation.checked, "flagged": moderation.flagged,
                           "categories": moderation.categories, "error": moderation.error},
        })
        if not dal.finish_plan(sess, plan_id, status=StageStatus.COMPLETE,
                               plan_json=json.dumps(parsed), validation_json=validation_json):
            # Superseded mid-flight (a re-POST took over) — drop the result; the new row owns
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
    # shipped here as an accidental self-join. Every new statement builder MUST be added.
    for _stmt in (_library_map_stmt("00000000-0000-0000-0000-000000000000"),
                  _standards_stmt([1])):
        _stmt.compile()

    # validated_actors: the stored dict shape round-trips; corrupt/mis-shaped blobs -> [].
    assert grounding.validated_actors('{"actors": ["APT x"], "validated": true}') == ["APT x"]
    assert grounding.validated_actors('{"actors": ["APT x"], "validated": false}') == []
    assert grounding.validated_actors("not json") == []
    assert grounding.validated_actors(None) == []

    # _validate_plan: structural violation raises; vocab violations warn but keep the row;
    # covered-with-recommendations inconsistency is flagged.
    bad_vocab = {
        "controls_to_be_implemented": [
            {"control_type": "quantum", "control_name": "X", "description": "d",
             "priority": "Urgent"}],
        "remediation_action_plan": [
            {"action_id": "A1", "action": "a", "owner": "SOC", "priority": "High"}],
        "applicable_to_all_subsystems": "Maybe", "control_coverage": "covered",
    }
    warns = _validate_plan(bad_vocab)
    assert any("control_type" in w for w in warns) and any("priority" in w for w in warns)
    assert any("applicable_to_all_subsystems" in w for w in warns)
    assert any("covered" in w for w in warns)  # covered + non-empty recommendations flagged
    assert _validate_plan({"controls_to_be_implemented": [], "remediation_action_plan": [],
                           "applicable_to_all_subsystems": "Yes",
                           "control_coverage": "covered"}) == []
    try:
        _validate_plan({"controls_to_be_implemented": "nope"})
        raise AssertionError("missing table must raise")
    except TreatmentPlanInvalid as e:
        assert "controls_to_be_implemented" in str(e) or "remediation_action_plan" in str(e)

    # _inject_reserved: server keys overwrite AI-emitted impostors; register echoes come from
    # the prompt-hidden block; the AI's controls table is NOT rewritten. The drift-pin assert
    # makes adding a key to _RESERVED_PLAN_KEYS without teaching the injector fail here.
    ai_table = [{"control_name": "MFA"}, {"control_name": "Backups"}]
    injected = _inject_reserved(
        {"treatment_plan": "Avoid", "risk_owner": "Dr. Evil",
         "controls_to_be_implemented": ai_table},
        {"register": {"risk_identification_date": "2026-06-14T08:31:00",
                      "risk_owner": "Head of OT Operations",
                      "impacted_business_division": "Water Treatment Operations"}})
    assert injected["treatment_plan"] == "Mitigate"
    assert injected["controls_to_be_implemented"] is ai_table  # AI-owned, injector hands off
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
    assert len(_clip("x" * (_FREE_TEXT_CAP + 500)) or "") == _FREE_TEXT_CAP

    # TreatmentConflict carries its wire reason.
    tc = TreatmentConflict("busy", reason=TreatmentGateReason.generation_in_progress)
    assert tc.reason == "generation_in_progress"
    print("treatment self-check ok")
