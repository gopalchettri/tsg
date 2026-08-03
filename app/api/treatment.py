"""Risk Treatment Plan routes — docs/RISK_TREATMENT_PLAN_SDD.md §5/§6.1.

Mounted by app/main.py ONLY when settings.risk_module_enabled (flag off → these paths 404 by
absence, zero handler code; the matching crm_* boot invariant lives in app/db/invariants.py).
Both routes are registered in app/api/route_audit.py::_ENTITY_SCOPED_ROUTES — registry entries
for an unmounted router are inert, but a mounted route missing from the registry fails boot.

POST reads the CRM Risk-module tables ONCE, freezes the redacted context into
InputSnapshotJSON, inserts the RUNNING plan row and enqueues; the GET on the same path is the
poll endpoint (no separate job-status route). The filtered unique index
UX_TreatmentPlan_ActiveOutput — not any SELECT — is the concurrent-POST arbiter.
"""
from __future__ import annotations

import json
from datetime import datetime

from fastapi import APIRouter, Depends
from sqlalchemy.exc import IntegrityError

from app.api.deps import Principal, get_principal
from app.api.schemas import (ErrorResponse, TreatmentPlanAccepted, TreatmentPlanBody,
                             TreatmentPlanStatus)
from app.api.sessions import get_authorized_session
from app.core.enums import AuditEventType, StageStatus, TreatmentGateReason
from app.core.logging import get_logger
from app.db import dal
from app.db import models as m
from app.db.engine import db_session
from app.pipeline import treatment
from app.pipeline.celery_app import generate_treatment_plan_task
from app.pipeline.tasks import ASSET_UNIT_ID

log = get_logger(__name__)

router = APIRouter(prefix="/v1", tags=["Treatment Plans"])

# Same declaration idea as sessions._CONFLICT_RESPONSES: typing the 409 puts
# TreatmentGateReason into /openapi.json so the UI can generate the reason codes.
_CONFLICT_RESPONSES: dict[int | str, dict] = {
    409: {"model": ErrorResponse, "description": "Conflict — see details.reason."}}

_TIMED_OUT_MESSAGE = "generation timed out — request it again"


def enqueue_treatment_plan(plan_id: str) -> None:
    """Indirection so tests can run the generation synchronously instead of via a broker."""
    generate_treatment_plan_task.delay(plan_id)


@router.post("/sessions/{session_id}/scenarios/{output_id}/treatment-plan", status_code=202,
             response_model=TreatmentPlanAccepted, responses=_CONFLICT_RESPONSES)
def post_treatment_plan(session_id: str, output_id: str, body: TreatmentPlanBody,
                        principal: Principal = Depends(get_principal)) -> TreatmentPlanAccepted:
    """Generate (or regenerate) the Mitigate treatment plan for one ACCEPTED scenario.

    Re-POST semantics: COMPLETE/ERROR plan → superseded and regenerated; fresh RUNNING plan →
    409 generation_in_progress; stale RUNNING plan (progress clock older than
    treatment_stale_seconds) → taken over. All CRM reads happen HERE — the worker and the GET
    only ever see the frozen snapshot."""
    with db_session() as sess:
        scenario_session = get_authorized_session(sess, session_id, principal)

        # Full session row + curator allowlists — the board load behind get_authorized_session
        # deliberately omits the AssetContextJSON/SubsystemsJSON blobs the snapshot needs.
        session_row = dal.load_session(sess, session_id)
        assert session_row is not None  # board load above already 404'd; same PK, same txn
        context_fields = dal.active_context_fields_by_group(sess)

        scn = dal.scenario_row(sess, session_id, output_id)
        if scn is None:
            raise dal.NotFoundError("scenario not found in this session")
        if scn["Superseded"]:
            raise treatment.TreatmentConflict(
                "this scenario was superseded by a regeneration — request the current one",
                reason=TreatmentGateReason.scenario_superseded)
        if scn["Accepted"] != 1:
            raise treatment.TreatmentConflict(
                "treatment plans are generated for accepted scenarios only",
                reason=TreatmentGateReason.scenario_not_accepted)

        crm = treatment.load_crm_risk_context(sess, body.crm_risk_identification_id)
        # Affirmative ownership only — absent, soft-deleted, NULL owner and foreign owner all
        # return the IDENTICAL 404: a client-supplied id must not become an existence oracle
        # (house rule: no proven owner = deny, dal.asset_owning_entities).
        if (crm is None or crm["group_id"] is None
                or str(crm["group_id"]) != scenario_session["EntityID"]):
            raise dal.NotFoundError("risk record not found")
        # NOTE (SDD §14.3): asset↔risk correlation via crm_assessment_asset is an open item —
        # the table has no column-level definition in the Risk DDD v0.1. Until it lands, the
        # risk is entity-correlated only.
        stored = (crm.get("stored_strategy") or "").strip()
        if stored and stored.lower() != "mitigate":
            raise treatment.TreatmentConflict(
                f"the risk register records treatment strategy '{stored}' for this risk — "
                "a Mitigate plan would contradict it",
                reason=TreatmentGateReason.strategy_mismatch)

        snapshot = treatment.build_treatment_input(
            sess, dict(session_row), dict(scn), crm, context_fields)

        plan_id = dal.guid()
        stale_cutoff = treatment._stale_cutoff()
        dal.supersede_active_plan(sess, scn["OutputID"], stale_cutoff)
        try:
            dal.insert_row(sess, m.Risk_Treatment_Plan, {
                "PlanID": plan_id, "SessionID": session_id, "OutputID": scn["OutputID"],
                "TenantID": session_row["TenantID"], "EntityID": session_row["EntityID"],
                "UserID": principal.user_id,
                "CrmRiskIdentificationID": body.crm_risk_identification_id,
                "TreatmentStrategy": body.treatment_strategy,
                "Status": str(StageStatus.RUNNING), "ActiveTaskID": None,
                "RiskIdentificationDate": crm.get("creation_date"),
                "InputSnapshotJSON": json.dumps(snapshot, default=str),
                "Superseded": 0, "CreatedAt": dal.now(), "UpdatedAt": dal.now(),
            })
            # Force the filtered-unique check NOW, inside this try — left to the context
            # manager's commit, the IntegrityError would fire outside it.
            sess.flush()
        except IntegrityError:
            sess.rollback()
            raise treatment.TreatmentConflict(
                "a treatment plan is already being generated for this scenario",
                reason=TreatmentGateReason.generation_in_progress) from None
        dal.append_audit(
            sess, AuditID=dal.guid(), SessionID=session_id,
            TenantID=session_row["TenantID"], EntityID=session_row["EntityID"],
            SubsystemID=ASSET_UNIT_ID, EventType=AuditEventType.treatment_plan_requested,
            ActorUserID=principal.user_id,
            DetailJSON=json.dumps({"plan_id": plan_id, "output_id": scn["OutputID"],
                                   "crm_risk_identification_id": body.crm_risk_identification_id}))

    # Enqueue OUTSIDE the db_session block (Pattern A). A failed enqueue must not wedge the
    # OutputID behind the staleness window: park the committed RUNNING row in ERROR, re-raise
    # (surfaces as the standard 500) — SDD §6.1 step 8.
    try:
        enqueue_treatment_plan(plan_id)
    except Exception:
        with db_session() as sess:
            dal.finish_plan(sess, plan_id, status=StageStatus.ERROR,
                            error_message="failed to queue generation — request it again")
        log.error("treatment.enqueue_failed", plan_id=plan_id)
        raise
    return TreatmentPlanAccepted(plan_id=plan_id, session_id=session_id,
                                 output_id=scn["OutputID"], status=str(StageStatus.RUNNING))


@router.get("/sessions/{session_id}/scenarios/{output_id}/treatment-plan",
            response_model=TreatmentPlanStatus)
def get_treatment_plan(session_id: str, output_id: str,
                       principal: Principal = Depends(get_principal)) -> TreatmentPlanStatus:
    """The poll endpoint — the scenario's one active plan row. 404 when no plan has ever been
    requested for this scenario. A stale RUNNING row is PRESENTED as ERROR/timed-out; the
    stored Status is not rewritten (no reaper — the next POST supersedes it instead)."""
    with db_session() as sess:
        get_authorized_session(sess, session_id, principal)
        row = dal.active_plan_row(sess, session_id, output_id)
        if row is None:
            raise dal.NotFoundError("no treatment plan has been requested for this scenario")

        status = row["Status"]
        error_message = row["ErrorMessage"]
        if status == str(StageStatus.RUNNING):
            updated = row["UpdatedAt"]
            if updated is not None and _naive_utc(updated) < _naive_utc(treatment._stale_cutoff()):
                status, error_message = str(StageStatus.ERROR), _TIMED_OUT_MESSAGE

        plan = _safe_json_dict(row["PlanJSON"], row["PlanID"])
        validation = _safe_json_dict(row["ValidationJSON"], row["PlanID"]) or {}
        moderation = validation.get("moderation") or {}
        return TreatmentPlanStatus(
            plan_id=row["PlanID"], session_id=row["SessionID"], output_id=row["OutputID"],
            status=status, treatment_strategy=row["TreatmentStrategy"],
            crm_risk_identification_id=row["CrmRiskIdentificationID"],
            risk_identification_date=row["RiskIdentificationDate"],
            plan=plan,
            warnings=[w for w in validation.get("warnings") or [] if isinstance(w, str)],
            moderation_flagged=bool(moderation.get("flagged")),
            error_message=error_message,
            created_at=row["CreatedAt"], completed_at=row["CompletedAt"])


def _safe_json_dict(blob: str | None, plan_id: str) -> dict | None:
    """Defensive PlanJSON/ValidationJSON parse — one corrupt blob must degrade to None with a
    log line, never 500 the poll (same posture as sessions._safe_scenario_json)."""
    if not blob:
        return None
    try:
        parsed = json.loads(blob)
    except (TypeError, ValueError):
        log.warning("treatment.stored_json_unparseable", plan_id=plan_id)
        return None
    return parsed if isinstance(parsed, dict) else None


def _naive_utc(dt: datetime) -> datetime:
    """MSSQL datetime2 comes back naive while dal.now() is aware — strip tzinfo on both sides
    so the staleness comparison never raises on the mismatch."""
    return dt.replace(tzinfo=None) if dt.tzinfo else dt
